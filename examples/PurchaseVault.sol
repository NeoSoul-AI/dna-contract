// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC3009} from "../interfaces/IERC3009.sol";

/**
 * @title PurchaseVault
 * @notice Reference integration for "pay token in, goods token out". The buyer does not need any
 *         native coin to pay for gas; the whole transaction can be submitted by a relayer.
 *
 * The main reason this contract exists is to express three integration rules as executable code:
 *
 * ─────────────────────────────────────────────────────────────────────────
 * Rule 1: integrating contracts must always use receiveWithAuthorization,
 *         never transferWithAuthorization
 * ─────────────────────────────────────────────────────────────────────────
 * transferWithAuthorization can be called by anyone. Once an attacker sees the buyer's signature
 * in the mempool, they can front-run it and submit that authorization "on its own":
 *
 *     the pay token really is transferred into this contract ✓
 *     but the nonce has been consumed                        ✗
 *     → the buyer's buyWithAuthorization call fails
 *     → the money ended up in the vault, but the buyer never received the goods
 *
 * No funds are stolen, but the books do not balance and it can only be fixed by manual
 * compensation. receiveWithAuthorization enforces msg.sender == to, and `to` is this contract, so
 * that authorization can **only** be triggered from inside this contract, which eliminates this
 * attack at the root.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * Rule 2: credit the accounting to `from`, not to msg.sender
 * ─────────────────────────────────────────────────────────────────────────
 * This function is designed so that anyone can submit it on the buyer's behalf (relayer mode), so
 * msg.sender may be the relayer, not the buyer. The payer is the `from` in the authorization. If
 * you delivered the goods to msg.sender, a relayer could simply take the goods as soon as it saw
 * the signature in the mempool.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * Rule 3: wrap permit in try/catch
 * ─────────────────────────────────────────────────────────────────────────
 * permit() can likewise be submitted by anyone. After an attacker submits it on its own, the nonce
 * has already been incremented, so the permit() inside your function will revert — even though the
 * authorization has in fact already taken effect. So a failing permit must be treated as "somebody
 * may already have submitted it for me"; just check the allowance afterwards.
 *
 * @dev This is a reference implementation for demonstration purposes: it illustrates how to
 *      integrate, and lets the tests reproduce the attacks described above. Before using it in
 *      production, adapt it to your own business logic (pricing, caps, refunds, pausing, etc.).
 */
contract PurchaseVault is ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice The token the buyer pays with (must support EIP-3009 / EIP-2612, e.g. USDC)
    IERC20 public immutable payToken;

    /// @notice The token the buyer receives
    IERC20 public immutable goodsToken;

    /// @notice Exchange rate: how much goodsToken 1 unit of payToken buys (scaled by 1e18)
    uint256 public immutable rate;

    event Purchased(address indexed buyer, uint256 paid, uint256 received, address indexed relayer);

    error ZeroAddress();
    error ZeroAmount();
    error InsufficientAllowance(uint256 have, uint256 need);
    error InsufficientGoods(uint256 have, uint256 need);

    constructor(address payToken_, address goodsToken_, uint256 rate_) {
        if (payToken_ == address(0) || goodsToken_ == address(0)) revert ZeroAddress();
        if (rate_ == 0) revert ZeroAmount();
        payToken = IERC20(payToken_);
        goodsToken = IERC20(goodsToken_);
        rate = rate_;
    }

    /**
     * @notice Buy using an EIP-3009 authorization. The buyer signs offline and anyone can submit
     *         this transaction on their behalf.
     * @dev The `to` in the authorization must be **this contract's address**. If you later wrap the
     *      call behind a router or a multicall, the msg.sender the token sees becomes that layer,
     *      and the authorization's `to` must change to that layer as well — this is a very common
     *      integration mistake.
     */
    function buyWithAuthorization(
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external nonReentrant {
        // Rule 1: the receive version, where msg.sender must equal `to` (i.e. this contract)
        IERC3009(address(payToken)).receiveWithAuthorization(
            from, address(this), value, validAfter, validBefore, nonce, signature
        );

        // Rule 2: deliver to `from`, not to msg.sender
        _deliver(from, value);
    }

    /**
     * @notice Buy using an EIP-2612 permit.
     * @dev The permit is wrapped in try/catch: an attacker can front-run it by submitting the same
     *      permit on its own, making the call here revert because the nonce has already been
     *      incremented — even though the allowance has in fact already taken effect. So a failure
     *      does not mean there is no authorization; checking the actual allowance below is the
     *      reliable test.
     */
    function buyWithPermit(
        address owner_,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
        // Rule 3
        try IERC20Permit(address(payToken)).permit(owner_, address(this), value, deadline, v, r, s) {
            // Normal path
        } catch {
            // It may have been front-run (the allowance is already in place), or the signature may
            // genuinely be invalid. Do not guess — look at the actual allowance, and if it is not
            // enough, revert with an explicit error rather than blindly calling transferFrom and
            // letting it throw a hard-to-diagnose ERC20 error.
            uint256 allowed = payToken.allowance(owner_, address(this));
            if (allowed < value) revert InsufficientAllowance(allowed, value);
        }

        payToken.safeTransferFrom(owner_, address(this), value);
        _deliver(owner_, value);
    }

    function _deliver(address buyer, uint256 paid) private {
        if (paid == 0) revert ZeroAmount();

        uint256 owed = (paid * rate) / 1e18;
        uint256 stock = goodsToken.balanceOf(address(this));
        if (stock < owed) revert InsufficientGoods(stock, owed);

        emit Purchased(buyer, paid, owed, _msgSenderCompat());
        goodsToken.safeTransfer(buyer, owed);
    }

    function _msgSenderCompat() private view returns (address) {
        return msg.sender;
    }
}
