# DE NEO AGENT (DNA) Contracts

Solidity sources for the **DE NEO AGENT** token (`DNA`) and its companion vesting contract.

| Contract | Purpose |
|----------|---------|
| `DeNeoAgent.sol` | Fixed-supply ERC-20 token with ERC-2612 `permit` and EIP-3009 gasless transfers. The production token. |
| `ERC3009.sol` | From-scratch EIP-3009 (Transfer With Authorization) implementation, mixed into the token. |
| `TokenVesting.sol` | Cliff + stepped/linear vesting for team, investor and ecosystem allocations. Owned by a Gnosis Safe. |
| `interfaces/IERC3009.sol` | External interface for contracts that want to accept EIP-3009 payments (compatible with USDC's surface). |
| `examples/PurchaseVault.sol` | Reference integration showing how to accept DNA payments safely without front-running risk. |
| `mocks/*.sol` | Test-only helpers. Never deployed. |

All contracts target `solidity 0.8.24` and build on OpenZeppelin Contracts v5.

---

## DeNeoAgent.sol

A plain ERC-20 with **no privileged functions at all**.

- **No mint.** `INITIAL_SUPPLY` of 1,000,000,000 DNA (18 decimals) is minted once in the constructor. No mint function exists, so `totalSupply()` can only ever go down.
- **No owner, no roles, no pause, no blacklist, no transfer fee, no proxy.** The deployed bytecode is final and there is nothing to govern. A multisig or timelock is unnecessary for the token itself.
- **Hardcoded name, symbol and supply.** These are constants in source rather than constructor arguments, so anyone reading the verified source can confirm they could not have been anything else.
- **Burnable.** Holders may burn their own balance (or an approved allowance) via `ERC20Burnable`, which permanently lowers supply.
- **Single constructor argument:** the treasury address that receives the whole supply. This is intended to be the Gnosis Safe, so tokens are under multisig control from the first block and never touch a hot wallet.

### Signature-based transfers

Two gasless authorization standards are supported. Both share one EIP-712 domain but use distinct type hashes, so a signature for one can never be replayed against the other.

| Standard | What is signed | Steps | Nonce |
|----------|----------------|-------|-------|
| ERC-2612 `permit` | An allowance | Two (permit, then `transferFrom`) | Sequential |
| EIP-3009 `transferWithAuthorization` | The transfer itself | One | Caller-chosen `bytes32`, parallel and individually cancellable |

Either lets a holder authorize a token movement offline; any third party (relayer) can then submit the transaction and pay the gas.

---

## ERC3009.sol

An abstract EIP-3009 implementation (OpenZeppelin does not ship one). Circle's FiatToken was used as the reference for comparison.

### Functions

- `transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, sig)` – callable by anyone.
- `receiveWithAuthorization(...)` – identical, but **only the payee (`to`) may submit it**. This is the variant integrating contracts must use.
- `cancelAuthorization(authorizer, nonce, sig)` – void an unredeemed authorization. Marks the nonce consumed permanently.
- `authorizationState(authorizer, nonce)` – `true` once a nonce has been redeemed or cancelled.

Every function has two overloads: the original `(v, r, s)` form and a `bytes signature` form that additionally accepts EIP-1271 contract-wallet signatures (e.g. a Gnosis Safe acting as the authorizer).

### Why `receiveWithAuthorization` matters

`transferWithAuthorization` can be submitted by anyone. If the payee is a contract that expects to run follow-up logic in the same transaction (deliver goods, mint a receipt, credit an account), an attacker can front-run the call and submit the bare authorization on its own. The funds arrive, the nonce is consumed, and the payee's logic never runs. `receiveWithAuthorization` enforces `msg.sender == to`, so the payment can only be pulled from inside the payee contract, making "collect payment" and "deliver goods" atomic.

### Signature verification order

The contract tries ECDSA recovery first and falls back to EIP-1271 only if that fails. This is the opposite of OpenZeppelin's `SignatureChecker`, and it is deliberate: on chains with EIP-7702, an EOA may delegate itself to a smart account and acquire code. Under OZ's ordering, an EIP-3009 authorization signed with that EOA's own key would stop validating while `permit` on the same token kept working. Checking ECDSA first keeps both standards behaving consistently, and grants no extra privilege because a 7702 delegation is itself authorized and revocable by that same key.

The ECDSA path rejects malleable signatures (upper-half `s`), invalid `v`, and any length other than 65 bytes.

### Time window

The authorization is valid strictly between `validAfter` and `validBefore` (`validAfter < block.timestamp < validBefore`), matching the EIP-3009 reference implementation.

---

## TokenVesting.sol

Lockup with a cliff followed by stepped or per-second linear release. Owned by a Gnosis Safe via `Ownable2Step`, with `ReentrancyGuard` on all token-moving paths.

```
released
   100% ┤                                   ┌────────
        │                            ┌──────┘
        │                     ┌──────┘
        │              ┌──────┘
     0% ┼──────────────┘
        └──────┬───────┬──────────────────┬──────────▶ time
             start   cliff              start+duration
```

- Before `cliff`: nothing is claimable.
- After `cliff`: released in steps of `slicePeriod` seconds, measured from `start`. `slicePeriod = 1` gives per-second linear release; `30 days` gives a monthly schedule.
- After `start + duration`: fully claimable.

### Creating schedules (owner only)

`createSchedule(beneficiary, amount, start, cliffDuration, duration, slicePeriod, revocable)` pulls the tokens from the owner in the same transaction, so a schedule can never exist without the tokens backing it. `createSchedulesBatch` creates many schedules with shared timing parameters in one multisig transaction.

Validation highlights:

- `start` **may be in the past**, to absorb multisig proposal-to-execution lag and to backfill vesting for people already on the team. Backdating is capped at `MAX_BACKDATE = 180 days`, so a 36-month schedule can be at most ~16.7% claimable at creation.
- Schedules that would already be fully matured at creation are rejected.
- `start + duration` is checked for `uint64` overflow so a schedule can never panic permanently once it matures.
- The amount recorded is the **balance actually received**, not the parameter passed, so fee-on-transfer tokens cannot leave the contract over-committed. (Rebasing tokens remain unsupported.)

### Claiming

- `release(scheduleId)` – release everything currently claimable.
- `release(scheduleId, amount)` – release a specific amount up to what is claimable.
- `releaseAll(scheduleIds[])` – release across many schedules; schedules with nothing claimable are skipped instead of reverting.

The beneficiary or the owner may trigger a release, but tokens always go to the beneficiary. The owner cannot redirect them.

### Beneficiary transfer

`transferBeneficiary(scheduleId, newBeneficiary)` lets a beneficiary migrate to a new wallet. **Only the current beneficiary can call it; the owner cannot.** If the owner could reassign beneficiaries, `revocable = false` would be meaningless.

### Revocation

`revoke(scheduleId, refundTo)` on a `revocable` schedule pays the already-vested portion to the beneficiary immediately and returns the unvested remainder to `refundTo`. Vesting is frozen at the revocation instant; `total` is never rewritten, so the historical curve stays queryable.

### Views

`getSchedule`, `schedulesOf`, `scheduleCount`, `releasableAmount`, `vestedAmount`, `vestedAmountAt(scheduleId, timestamp)` (for plotting the curve at any past or future time), and `totalReleasableOf(beneficiary)`.

### Recovery and safety rails

- `renounceOwnership()` is disabled. Ownership changes only via `transferOwnership` + `acceptOwnership`, so the owner can never become `address(0)` and strand revocation and recovery.
- `recoverExcess(to)` withdraws only `balance - totalCommitted`, so it can never touch tokens belonging to a schedule.
- `recoverForeignToken(erc20, to)` retrieves any *other* ERC-20 sent by mistake and explicitly rejects the vested token.
- The `Schedule` struct is packed into three storage slots; the field order is documented in source and should not be changed casually.

---

## Integrating: examples/PurchaseVault.sol

A reference "pay DNA in, receive goods token out" contract. It exists to express three rules as executable code:

1. **Always use `receiveWithAuthorization`, never `transferWithAuthorization`,** when the payee is a contract. Otherwise the payment can be front-run and the buyer never receives the goods.
2. **Credit the payer (`from`), not `msg.sender`.** In relayer mode `msg.sender` is the relayer.
3. **Wrap `permit` in `try/catch`,** then check the actual allowance. A front-run permit reverts even though the allowance is already in place.

Note that the authorization's `to` must be the contract that calls `receiveWithAuthorization`. If you route the call through a router or multicall, `to` must be that layer instead.

`mocks/NaiveVault.sol` is the deliberately vulnerable counter-example that makes both mistakes; the test suite reproduces the attacks against it. **Never deploy it.**

---

## Mocks (test only)

| File | Role |
|------|------|
| `MockERC1271Signer.sol` | 1-of-1 EIP-1271 wallet, stands in for a Gnosis Safe authorizer. |
| `MockFeeToken.sol` | 2% fee-on-transfer ERC-20, verifies that `TokenVesting` records received rather than requested amounts. |
| `MockSafe.sol` | Minimal Safe surface (`getOwners`, `getThreshold`, `VERSION`) for deployment pre-checks. |
| `NaiveVault.sol` | Vulnerable integration used to reproduce front-running and relayer-theft attacks. |

---

## Deployment model

1. Deploy `DeNeoAgent(treasury)` with the Gnosis Safe as `treasury`. The entire supply lands in the Safe.
2. Deploy `TokenVesting(token, owner)` with the DNA address and the Safe as owner.
3. From the Safe: `approve` the vesting contract, then `createSchedule` / `createSchedulesBatch`.

The token itself needs no further administration. All ongoing governance (creating schedules, revoking, recovering stray tokens) lives in `TokenVesting` and is exercised by the Safe.

## License

MIT
