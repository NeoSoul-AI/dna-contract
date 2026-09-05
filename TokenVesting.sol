// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title TokenVesting
 * @notice Token lockup with a cliff followed by stepped (or fully linear) release.
 *
 * Release curve:
 *
 *   released
 *      100% ┤                                   ┌────────
 *           │                            ┌──────┘
 *           │                     ┌──────┘
 *           │              ┌──────┘
 *        0% ┼──────────────┘
 *           └──────┬───────┬──────────────────┬──────────▶ time
 *                start   cliff              start+duration
 *
 * - Before the cliff: zero. Nothing is claimable.
 * - After the cliff: released in steps of slicePeriod.
 *     slicePeriod = 1        -> per-second linear release (smoothest)
 *     slicePeriod = 30 days  -> one batch per month (the usual stepped schedule)
 * - After start + duration: the full amount is claimable.
 *
 * Funding: the owner (a Gnosis Safe) approves this contract, then calls
 * createSchedule. The tokens are pulled into this contract in the same
 * transaction that creates the schedule, so a schedule can never exist without
 * the tokens backing it.
 */
contract TokenVesting is Ownable2Step, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /**
     * @dev Field order is chosen for storage packing. Before reordering, check
     *      whether the change costs an extra slot:
     *        slot0  beneficiary(20) + start(8) + revocable(1)                = 29 bytes
     *        slot1  cliff(8) + duration(8) + slicePeriod(8) + revokedAt(8)   = 32 bytes
     *        slot2  total(16) + released(16)                                 = 32 bytes
     *      Moving `revocable` to the end gives it a slot of its own and costs
     *      roughly 20k extra gas per schedule created (measured).
     */
    struct Schedule {
        address beneficiary; // Recipient of the released tokens
        uint64 start; // Vesting start (unix seconds). May be in the past; see createSchedule
        bool revocable; // Whether the owner may revoke the unvested remainder
        uint64 cliff; // Absolute timestamp: start + cliffDuration
        uint64 duration; // Total vesting length in seconds, measured from start
        uint64 slicePeriod; // Release granularity in seconds; 1 = per-second linear
        uint64 revokedAt; // Revocation timestamp; 0 = not revoked. Vesting freezes at this instant
        uint128 total; // Original allocation. Never rewritten on revoke, so the
        // historical vesting curve stays queryable
        uint128 released; // Amount already claimed
    }

    /**
     * @notice How far into the past `start` may be backdated.
     * @dev Backdating itself is necessary (multisig proposal-to-execution lag, and
     *      granting vesting to an already-employed person), but without a ceiling it
     *      becomes a parameter that is very hard to review: a signer looking at the
     *      Safe UI sees a raw uint64, not a date. A schedule that reads as "36-month
     *      vesting" could in fact be 90% claimable the moment it is created.
     *
     *      Why 180 days: there are two legitimate uses. The multisig lag is days to
     *      about two weeks, and backfilling an existing employee's tenure can run to
     *      several months. A 90-day ceiling puts the common "hired three months ago"
     *      case right on the boundary, which is too tight. 180 days covers both while
     *      still bounding the worst case: a 36-month schedule backdated to the limit
     *      is only 16.7% claimable at creation, not close to 100%.
     */
    uint64 public constant MAX_BACKDATE = 180 days;

    /// @notice The token held under vesting. Immutable after deployment.
    IERC20 public immutable token;

    /// @notice Sum across all schedules of tokens allocated but not yet released.
    ///         This contract must always hold at least this balance.
    uint256 public totalCommitted;

    uint256 private _nextScheduleId;

    mapping(uint256 scheduleId => Schedule) private _schedules;
    mapping(address beneficiary => uint256[] scheduleIds) private _beneficiarySchedules;

    event ScheduleCreated(
        uint256 indexed scheduleId,
        address indexed beneficiary,
        uint256 amount,
        uint64 start,
        uint64 cliff,
        uint64 duration,
        uint64 slicePeriod,
        bool revocable
    );
    event Released(uint256 indexed scheduleId, address indexed beneficiary, uint256 amount);
    event BeneficiaryTransferred(
        uint256 indexed scheduleId, address indexed from, address indexed to
    );
    event Revoked(uint256 indexed scheduleId, uint256 vestedReleased, uint256 refunded);
    event ExcessRecovered(address indexed to, uint256 amount);
    event ForeignTokenRecovered(address indexed erc20, address indexed to, uint256 amount);

    error ZeroAddress();
    error ZeroAmount();
    error InvalidDuration();
    error InvalidSlicePeriod();
    error CliffExceedsDuration();
    error ScheduleAlreadyEnded(uint64 start, uint64 duration);
    error StartTooFarInPast(uint64 start, uint64 earliestAllowed);
    error NothingReceived();
    error NotBeneficiary(address caller, address beneficiary);
    error SameBeneficiary();
    error RenounceOwnershipDisabled();
    error AmountTooLarge();
    error ScheduleNotFound(uint256 scheduleId);
    error NotBeneficiaryOrOwner();
    error NotRevocable();
    error AlreadyRevoked();
    error NothingToRelease();
    error ReleaseAmountExceedsVested(uint256 requested, uint256 available);
    error NoExcessBalance();
    error CannotRecoverVestedToken();

    constructor(address token_, address owner_) Ownable(owner_) {
        if (token_ == address(0) || owner_ == address(0)) revert ZeroAddress();
        token = IERC20(token_);
    }

    // ---------------------------------------------------------------------
    // Schedule creation (owner = Gnosis Safe)
    // ---------------------------------------------------------------------

    /**
     * @notice Create a vesting schedule and pull the tokens from the owner into
     *         this contract in the same transaction.
     * @dev The owner must have approved at least `amount` to this contract first.
     *
     * **`start` is allowed to be in the past.** This is deliberate, for two reasons:
     *
     * 1. The owner is a multisig. Collecting signatures can take hours or days,
     *    while `start` is fixed in the calldata at proposal time. Requiring
     *    `start >= block.timestamp` would make a transaction proposed on Monday and
     *    executed on Wednesday revert: gas wasted, and another signing round needed.
     * 2. Backfilling: an employee hired three months ago should have vesting that
     *    starts from their hire date.
     *
     * Only schedules that have *already fully matured* at creation are rejected.
     * Such a schedule provides no lockup at all and is almost certainly a mistake.
     *
     * The trade-off is that a heavily backdated schedule is partly claimable the
     * moment it is created. That is the owner's decision and the contract does not
     * prevent it beyond MAX_BACKDATE, but scripts/vesting.ts computes and displays
     * the immediately-claimable percentage before the batch is signed.
     *
     * @param beneficiary   Recipient of the released tokens
     * @param amount        Total amount to lock (wei)
     * @param start         Vesting start (unix seconds). May be in the past, but
     *                      start + duration must still be in the future
     * @param cliffDuration Cliff length in seconds, measured from start; 0 = no cliff
     * @param duration      Total vesting length in seconds; must be > 0 and >= cliffDuration
     * @param slicePeriod   Release granularity in seconds; must be > 0 and <= duration
     * @param revocable     Whether the owner may later revoke the unvested remainder
     * @return scheduleId   Id of the newly created schedule
     */
    function createSchedule(
        address beneficiary,
        uint256 amount,
        uint64 start,
        uint64 cliffDuration,
        uint64 duration,
        uint64 slicePeriod,
        bool revocable
    ) public onlyOwner nonReentrant returns (uint256 scheduleId) {
        if (beneficiary == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (amount > type(uint128).max) revert AmountTooLarge();
        if (duration == 0) revert InvalidDuration();
        if (slicePeriod == 0 || slicePeriod > duration) revert InvalidSlicePeriod();
        if (cliffDuration > duration) revert CliffExceedsDuration();
        // start + duration is evaluated on every vesting calculation. Reject uint64
        // overflow here: otherwise the schedule panics permanently once it matures,
        // and the tokens locked inside cannot be recovered even with revoke.
        if (uint256(start) + uint256(duration) > type(uint64).max) revert InvalidDuration();
        // Already fully matured at creation: no lockup effect whatsoever, so this is
        // certainly a parameter mistake rather than an intent.
        if (uint256(start) + uint256(duration) <= block.timestamp) {
            revert ScheduleAlreadyEnded(start, duration);
        }
        // Backdating is capped. Without a cap a schedule could be almost entirely
        // unlocked at creation, and a signer reviewing it in the Safe UI sees only a
        // raw timestamp, which makes that very hard to notice.
        if (block.timestamp > MAX_BACKDATE && start < block.timestamp - MAX_BACKDATE) {
            revert StartTooFarInPast(start, uint64(block.timestamp - MAX_BACKDATE));
        }

        // Measure what was actually received rather than trusting the parameter.
        // For a standard ERC20 the two are equal. But if this contract is ever used
        // to lock a fee-on-transfer token, recording 100 while receiving 98 would
        // leave the contract permanently over-committed: the last beneficiaries
        // could not be paid, and recoverExcess could not fix it either, because the
        // books would show no excess balance.
        // Note this does not make rebasing tokens safe: their balances change
        // after the fact, which no measurement at creation time can account for.
        uint256 before = token.balanceOf(address(this));
        token.safeTransferFrom(_msgSender(), address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        if (received == 0) revert NothingReceived();
        if (received > type(uint128).max) revert AmountTooLarge();

        scheduleId = _nextScheduleId++;
        _schedules[scheduleId] = Schedule({
            beneficiary: beneficiary,
            start: start,
            revocable: revocable,
            cliff: start + cliffDuration,
            duration: duration,
            slicePeriod: slicePeriod,
            revokedAt: 0,
            total: uint128(received),
            released: 0
        });
        _beneficiarySchedules[beneficiary].push(scheduleId);
        totalCommitted += received;

        emit ScheduleCreated(
            scheduleId, beneficiary, received, start, start + cliffDuration, duration, slicePeriod, revocable
        );
    }

    /// @notice Create several schedules that share the same timing parameters.
    /// @dev Saves gas and, more importantly, lets the multisig sign one transaction
    ///      instead of one per beneficiary. Each entry still goes through the full
    ///      validation in createSchedule.
    function createSchedulesBatch(
        address[] calldata beneficiaries,
        uint256[] calldata amounts,
        uint64 start,
        uint64 cliffDuration,
        uint64 duration,
        uint64 slicePeriod,
        bool revocable
    ) external onlyOwner returns (uint256[] memory scheduleIds) {
        uint256 len = beneficiaries.length;
        require(len == amounts.length, "length mismatch");
        scheduleIds = new uint256[](len);
        for (uint256 i = 0; i < len; ++i) {
            scheduleIds[i] =
                createSchedule(beneficiaries[i], amounts[i], start, cliffDuration, duration, slicePeriod, revocable);
        }
    }

    // ---------------------------------------------------------------------
    // Claiming
    // ---------------------------------------------------------------------

    /// @notice Release everything currently claimable on a schedule.
    /// @dev Either the beneficiary or the owner may trigger this, but the tokens are
    ///      always sent to the beneficiary. The owner cannot redirect them.
    function release(uint256 scheduleId) external {
        _release(scheduleId, type(uint256).max);
    }

    /// @notice Release a specific amount from a schedule, up to what is claimable.
    function release(uint256 scheduleId, uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        _release(scheduleId, amount);
    }

    /**
     * @notice Release from several schedules in one transaction.
     * @dev Schedules with nothing currently claimable (revoked, or still before the
     *      cliff) are skipped rather than reverting, so a beneficiary can pass the
     *      whole list returned by schedulesOf() without filtering it first.
     *      Reverts only when no schedule in the list had anything to release.
     */
    function releaseAll(uint256[] calldata scheduleIds) external {
        bool released = false;
        for (uint256 i = 0; i < scheduleIds.length; ++i) {
            uint256 id = scheduleIds[i];
            Schedule storage s = _schedules[id];
            if (s.beneficiary == address(0)) revert ScheduleNotFound(id);
            if (_vestedAmount(s, uint64(block.timestamp)) > s.released) {
                _release(id, type(uint256).max);
                released = true;
            }
        }
        if (!released) revert NothingToRelease();
    }

    function _release(uint256 scheduleId, uint256 amount) private nonReentrant {
        Schedule storage s = _schedules[scheduleId];
        if (s.beneficiary == address(0)) revert ScheduleNotFound(scheduleId);
        if (_msgSender() != s.beneficiary && _msgSender() != owner()) revert NotBeneficiaryOrOwner();

        uint256 releasable = _releasableAmount(s);
        if (releasable == 0) revert NothingToRelease();
        if (amount == type(uint256).max) {
            amount = releasable;
        } else if (amount > releasable) {
            revert ReleaseAmountExceedsVested(amount, releasable);
        }

        s.released += uint128(amount);
        totalCommitted -= amount;

        emit Released(scheduleId, s.beneficiary, amount);
        token.safeTransfer(s.beneficiary, amount);
    }

    // ---------------------------------------------------------------------
    // Beneficiary transfer
    // ---------------------------------------------------------------------

    /**
     * @notice Move a schedule to a different beneficiary address.
     *
     * **Only the current beneficiary may call this. The owner cannot.** This matters:
     * if the owner could reassign beneficiaries, the `revocable = false` guarantee
     * would be worthless, because the multisig could simply point the schedule at
     * itself and take the allocation. No owner path is provided here for that reason.
     *
     * The function exists so a beneficiary can migrate wallets (for example after a
     * key-compromise scare). Without it, a non-revocable schedule would be stuck on
     * its original address forever, and if that key ever became unusable the tokens
     * would be permanently frozen with no recovery path for anyone.
     *
     * @dev Revoked schedules may also be transferred: they can still hold a vested
     *      but unclaimed balance.
     */
    function transferBeneficiary(uint256 scheduleId, address newBeneficiary) external {
        Schedule storage s = _schedules[scheduleId];
        address current = s.beneficiary;
        if (current == address(0)) revert ScheduleNotFound(scheduleId);
        if (_msgSender() != current) revert NotBeneficiary(_msgSender(), current);
        if (newBeneficiary == address(0)) revert ZeroAddress();
        if (newBeneficiary == current) revert SameBeneficiary();

        s.beneficiary = newBeneficiary;

        // Maintain the reverse index: swap-and-pop out of the old beneficiary's list,
        // then append to the new beneficiary's list.
        uint256[] storage ids = _beneficiarySchedules[current];
        uint256 len = ids.length;
        for (uint256 i = 0; i < len; ++i) {
            if (ids[i] == scheduleId) {
                ids[i] = ids[len - 1];
                ids.pop();
                break;
            }
        }
        _beneficiarySchedules[newBeneficiary].push(scheduleId);

        emit BeneficiaryTransferred(scheduleId, current, newBeneficiary);
    }

    // ---------------------------------------------------------------------
    // Revocation
    // ---------------------------------------------------------------------

    /**
     * @notice Revoke a revocable schedule. The already-vested portion is paid to the
     *         beneficiary immediately; the unvested remainder is returned to
     *         `refundTo` (normally the Gnosis Safe).
     * @dev Reverts on a non-revocable schedule and on a schedule already revoked.
     *      The longer a revocation is delayed, the more has vested and the less
     *      comes back.
     */
    function revoke(uint256 scheduleId, address refundTo) external onlyOwner nonReentrant {
        Schedule storage s = _schedules[scheduleId];
        if (s.beneficiary == address(0)) revert ScheduleNotFound(scheduleId);
        if (!s.revocable) revert NotRevocable();
        if (s.revokedAt != 0) revert AlreadyRevoked();
        if (refundTo == address(0)) revert ZeroAddress();

        uint256 vested = _vestedAmount(s, uint64(block.timestamp));
        uint256 releasable = vested - uint256(s.released);
        uint256 unvested = uint256(s.total) - vested;

        // Record the revocation instant. Vesting freezes here, and `total` keeps the
        // original allocation rather than being rewritten, so querying the vesting
        // curve at any historical timestamp still returns the correct value.
        s.revokedAt = uint64(block.timestamp);
        s.released += uint128(releasable);
        totalCommitted -= (releasable + unvested);

        emit Revoked(scheduleId, releasable, unvested);

        address beneficiary = s.beneficiary;
        if (releasable > 0) {
            emit Released(scheduleId, beneficiary, releasable);
            token.safeTransfer(beneficiary, releasable);
        }
        if (unvested > 0) {
            token.safeTransfer(refundTo, unvested);
        }
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function getSchedule(uint256 scheduleId) external view returns (Schedule memory) {
        Schedule memory s = _schedules[scheduleId];
        if (s.beneficiary == address(0)) revert ScheduleNotFound(scheduleId);
        return s;
    }

    function schedulesOf(address beneficiary) external view returns (uint256[] memory) {
        return _beneficiarySchedules[beneficiary];
    }

    function scheduleCount() external view returns (uint256) {
        return _nextScheduleId;
    }

    /// @notice Amount currently claimable on this schedule.
    function releasableAmount(uint256 scheduleId) external view returns (uint256) {
        Schedule memory s = _schedules[scheduleId];
        if (s.beneficiary == address(0)) revert ScheduleNotFound(scheduleId);
        return _releasableAmount(s);
    }

    /// @notice Cumulative amount vested so far, including what has already been released.
    function vestedAmount(uint256 scheduleId) external view returns (uint256) {
        Schedule memory s = _schedules[scheduleId];
        if (s.beneficiary == address(0)) revert ScheduleNotFound(scheduleId);
        return _vestedAmount(s, uint64(block.timestamp));
    }

    /// @notice Cumulative vested amount at an arbitrary timestamp, for plotting the
    ///         release curve in a front end. Works for past and future timestamps.
    function vestedAmountAt(uint256 scheduleId, uint64 timestamp) external view returns (uint256) {
        Schedule memory s = _schedules[scheduleId];
        if (s.beneficiary == address(0)) revert ScheduleNotFound(scheduleId);
        return _vestedAmount(s, timestamp);
    }

    /// @notice Total currently claimable across all of one beneficiary's schedules.
    function totalReleasableOf(address beneficiary) external view returns (uint256 sum) {
        uint256[] storage ids = _beneficiarySchedules[beneficiary];
        for (uint256 i = 0; i < ids.length; ++i) {
            sum += _releasableAmount(_schedules[ids[i]]);
        }
    }

    function _releasableAmount(Schedule memory s) private view returns (uint256) {
        return _vestedAmount(s, uint64(block.timestamp)) - s.released;
    }

    function _vestedAmount(Schedule memory s, uint64 timestamp) private pure returns (uint256) {
        // Revoked schedule: vesting is frozen at the revocation instant, so the
        // passage of time after revocation adds nothing.
        if (s.revokedAt != 0 && timestamp > s.revokedAt) timestamp = s.revokedAt;

        if (timestamp < s.cliff) return 0;
        if (timestamp >= s.start + s.duration) return s.total;

        uint256 elapsed = timestamp - s.start;
        // Round down to the last slice boundary, which produces the stepped release.
        // Note the boundaries are measured from `start`, not from `cliff`: if the cliff
        // is not a whole multiple of slicePeriod, the amount claimable at the cliff is
        // less than cliff/duration would suggest. See TOKENOMICS.md for a worked example.
        uint256 vestedSeconds = (elapsed / s.slicePeriod) * s.slicePeriod;
        return (uint256(s.total) * vestedSeconds) / s.duration;
    }

    // ---------------------------------------------------------------------
    // Recovery
    // ---------------------------------------------------------------------

    /**
     * @notice Disables Ownable's built-in ownership renouncement.
     * @dev If the Safe were to call renounceOwnership() by mistake, the owner would
     *      become address(0) and revoke(), recoverExcess(), recoverForeignToken() and
     *      createSchedule() would all be permanently dead: revocable schedules could
     *      never be revoked, and tokens sent here by accident could never be retrieved.
     *      To change owner, use Ownable2Step's transferOwnership + acceptOwnership,
     *      which requires the new owner to actively accept and so cannot be
     *      misdirected to an address nobody controls.
     */
    function renounceOwnership() public pure override {
        revert RenounceOwnershipDisabled();
    }

    /// @notice Retrieve vested-token balance that was sent here by mistake and is not
    ///         committed to any schedule.
    /// @dev Withdraws only balance minus totalCommitted, so it can never touch tokens
    ///      belonging to a schedule.
    function recoverExcess(address to) external onlyOwner nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        uint256 balance = token.balanceOf(address(this));
        if (balance <= totalCommitted) revert NoExcessBalance();
        uint256 excess = balance - totalCommitted;
        emit ExcessRecovered(to, excess);
        token.safeTransfer(to, excess);
    }

    /// @notice Retrieve some *other* ERC20 sent here by mistake.
    /// @dev Explicitly rejects the vested token, so this cannot be used as a back door
    ///      to drain tokens that belong to schedules.
    function recoverForeignToken(address erc20, address to) external onlyOwner nonReentrant {
        if (erc20 == address(token)) revert CannotRecoverVestedToken();
        if (to == address(0)) revert ZeroAddress();
        uint256 balance = IERC20(erc20).balanceOf(address(this));
        if (balance == 0) revert ZeroAmount();
        emit ForeignTokenRecovered(erc20, to, balance);
        IERC20(erc20).safeTransfer(to, balance);
    }
}
