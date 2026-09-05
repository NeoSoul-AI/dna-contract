// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC3009} from "./ERC3009.sol";

/**
 * @title DE NEO AGENT
 * @notice Fixed-supply ERC20 token. This is the production contract.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * This contract has no privileged functions. Not one.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * No mint      - supply can never increase. Not "we promise not to", but
 *                "the function does not exist".
 * No owner     - no admin, no AccessControl, no roles.
 * No pause     - nobody can freeze transfers.
 * No blacklist - nobody can freeze a holder's balance.
 * No transfer fee - send 100 tokens, the recipient receives 100 tokens.
 * No upgrade path - this is not a proxy. The deployed bytecode is final.
 *
 * Consequently no multisig or timelock is needed to govern this contract:
 * there is nothing to govern. The Gnosis Safe's only roles are holding the
 * treasury balance and owning the separate TokenVesting contract.
 *
 * Name, symbol and total supply are hardcoded in the source rather than passed
 * as constructor arguments. Anyone reading the verified source can therefore see
 * that these three values could not have been anything else, which also removes
 * the entire class of "wrong constructor parameter at deployment" errors.
 *
 * Signature-based authorization standards supported:
 *   ERC-2612 (permit)                    signs an allowance; anyone may then call transferFrom
 *   ERC-3009 (transferWithAuthorization) signs the transfer itself; one step, cancellable nonce
 * Both share one EIP-712 domain but use distinct type hashes, so a signature for
 * one can never be replayed against the other. Both let a holder authorize a
 * movement of tokens without holding native coin for gas: the signature is made
 * offline and any third party may submit the transaction.
 *
 * @dev totalSupply() is monotonically non-increasing. INITIAL_SUPPLY is minted
 *      once in the constructor and is therefore the all-time high. ERC20Burnable
 *      lets a holder burn their own balance (or an approved allowance), which
 *      lowers totalSupply(). That direction is one-way: burned supply cannot be
 *      restored, because no minting path exists.
 */
contract DeNeoAgent is ERC20, ERC20Burnable, ERC20Permit, ERC3009 {
    /// @notice Amount minted once at deployment: 1,000,000,000 tokens (18 decimals).
    ///         This is the absolute ceiling on supply for the life of the contract.
    uint256 public constant INITIAL_SUPPLY = 1_000_000_000 ether;

    error ZeroAddress();

    /**
     * @param treasury Address receiving the entire 1,000,000,000 supply. This should
     *                 be the Gnosis Safe, so the tokens are under multisig protection
     *                 from the first block and never pass through the deployer's
     *                 hot wallet.
     */
    constructor(address treasury) ERC20("DE NEO AGENT", "DNA") ERC20Permit("DE NEO AGENT") {
        if (treasury == address(0)) revert ZeroAddress();
        _mint(treasury, INITIAL_SUPPLY);
    }
}
