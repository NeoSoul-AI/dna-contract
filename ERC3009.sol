// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/**
 * @title ERC3009
 * @notice EIP-3009: Transfer With Authorization.
 *
 * Lets a holder sign an authorization offline which any third party may then
 * submit on chain, so the holder never needs native coin for gas. Differences
 * from ERC-2612 (permit):
 *
 *   ERC-2612  signs an allowance; somebody must still call transferFrom (two steps).
 *             The nonce is sequential, so multiple signatures from one holder must
 *             be redeemed in order.
 *   ERC-3009  signs the transfer itself; one step.
 *             The nonce is a caller-chosen bytes32, so authorizations may be issued
 *             in parallel and individually cancelled.
 *
 * Both share one EIP-712 domain but use distinct type hashes, so a signature made
 * for one standard can never be replayed against the other.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * Why receiveWithAuthorization exists: front-running protection
 * ─────────────────────────────────────────────────────────────────────────
 * Anyone may submit a transferWithAuthorization. When the payee is a contract
 * that expects to run follow-up logic in the same transaction as the incoming
 * payment, an attacker can front-run it by submitting the authorization on its
 * own. The funds arrive, but the payee contract's logic never executes, and the
 * authorization nonce is consumed so the payer cannot simply retry.
 *
 * receiveWithAuthorization enforces msg.sender == to, meaning only the payee may
 * submit it. A receiving contract can therefore bind "collect payment" and
 * "deliver goods" into a single atomic call. Contract integrations must always
 * use this variant; see INTEGRATION.md for a reproduced attack.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * @dev This is a from-scratch implementation of EIP-3009, not an OpenZeppelin
 *      component (OZ does not ship one). Circle's FiatToken was used as the
 *      reference implementation for comparison. Attack surfaces covered by the
 *      test suite: signature replay (same authorization twice, across chains,
 *      across contracts, across authorization types, and permit signatures reused
 *      as authorizations), signature malleability, nonce collision between
 *      different authorizers, front-running, expired and not-yet-valid time
 *      windows, and whether a failed transfer consumes the nonce.
 *
 *      Both 65-byte EOA signatures and EIP-1271 contract signatures (e.g. a
 *      Gnosis Safe acting as authorizer) are accepted.
 */
abstract contract ERC3009 is ERC20, EIP712 {
    // keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

    // keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;

    // keccak256("CancelAuthorization(address authorizer,bytes32 nonce)")
    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;

    /// @dev authorizer => nonce => consumed. Both redemption and cancellation set this,
    ///      so a cancelled nonce can never later be redeemed.
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

    error AuthorizationNotYetValid(uint256 validAfter);
    error AuthorizationExpired(uint256 validBefore);
    error AuthorizationAlreadyUsed(address authorizer, bytes32 nonce);
    error InvalidAuthorizationSignature();
    error CallerMustBePayee(address caller, address payee);

    /// @notice Returns true if this authorizer's nonce has been redeemed or cancelled.
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool) {
        return _authorizationStates[authorizer][nonce];
    }

    // ---------------------------------------------------------------------
    // transferWithAuthorization
    // ---------------------------------------------------------------------

    /// @notice Execute a transfer against a signed authorization.
    /// @dev Callable by anyone. If the payee is a contract that runs follow-up logic,
    ///      use receiveWithAuthorization instead: this variant can be front-run.
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        _transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, abi.encodePacked(r, s, v));
    }

    /// @notice As above, but accepts a variable-length signature, which additionally
    ///         supports EIP-1271 contract wallets such as a Gnosis Safe.
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external {
        _transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, signature);
    }

    // ---------------------------------------------------------------------
    // receiveWithAuthorization (only the payee may submit - front-running protection)
    // ---------------------------------------------------------------------

    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        _receiveWithAuthorization(from, to, value, validAfter, validBefore, nonce, abi.encodePacked(r, s, v));
    }

    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external {
        _receiveWithAuthorization(from, to, value, validAfter, validBefore, nonce, signature);
    }

    // ---------------------------------------------------------------------
    // cancelAuthorization
    // ---------------------------------------------------------------------

    /// @notice Void an authorization that has not been redeemed yet.
    /// @dev The signature must come from the authorizer. Marks the nonce consumed,
    ///      so the original authorization can never be redeemed afterwards.
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)
        external
    {
        _cancelAuthorization(authorizer, nonce, abi.encodePacked(r, s, v));
    }

    function cancelAuthorization(address authorizer, bytes32 nonce, bytes memory signature) external {
        _cancelAuthorization(authorizer, nonce, signature);
    }

    // ---------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------

    function _transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) private {
        _requireValidWindow(validAfter, validBefore);
        _requireUnusedAuthorization(from, nonce);

        bytes32 structHash = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce
            )
        );
        _requireValidSignature(from, structHash, signature);

        _markAuthorizationUsed(from, nonce);
        _transfer(from, to, value);
    }

    function _receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) private {
        // This single line is the entire reason the receive variant exists.
        if (_msgSender() != to) revert CallerMustBePayee(_msgSender(), to);

        _requireValidWindow(validAfter, validBefore);
        _requireUnusedAuthorization(from, nonce);

        bytes32 structHash = keccak256(
            abi.encode(
                RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce
            )
        );
        _requireValidSignature(from, structHash, signature);

        _markAuthorizationUsed(from, nonce);
        _transfer(from, to, value);
    }

    function _cancelAuthorization(address authorizer, bytes32 nonce, bytes memory signature) private {
        _requireUnusedAuthorization(authorizer, nonce);

        bytes32 structHash = keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce));
        _requireValidSignature(authorizer, structHash, signature);

        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    function _requireValidWindow(uint256 validAfter, uint256 validBefore) private view {
        // Strict inequalities on both bounds, matching the EIP-3009 reference
        // implementation: the authorization is valid strictly between the two timestamps.
        if (block.timestamp <= validAfter) revert AuthorizationNotYetValid(validAfter);
        if (block.timestamp >= validBefore) revert AuthorizationExpired(validBefore);
    }

    function _requireUnusedAuthorization(address authorizer, bytes32 nonce) private view {
        if (_authorizationStates[authorizer][nonce]) {
            revert AuthorizationAlreadyUsed(authorizer, nonce);
        }
    }

    function _markAuthorizationUsed(address authorizer, bytes32 nonce) private {
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationUsed(authorizer, nonce);
    }

    /**
     * @dev Try ECDSA first, then EIP-1271. This ordering is deliberate.
     *
     *      OpenZeppelin's SignatureChecker treats any address with code as a
     *      contract and validates via EIP-1271 only. BSC has EIP-7702 enabled, so
     *      an EOA may delegate itself to a smart account, at which point
     *      code.length != 0 for that EOA. Under OZ's ordering, an ERC-3009
     *      authorization signed by that EOA's own private key would suddenly stop
     *      validating, while permit on this same token would keep working, because
     *      OZ's ERC20Permit calls ECDSA.recover directly. Two signature standards
     *      on one token behaving differently is a trap for integrators, and this
     *      contract has no upgrade path to fix it later.
     *
     *      Checking ECDSA first is not a privilege escalation. A 7702 delegation is
     *      itself authorized by that private key and revocable by it at any time, so
     *      honouring the key's own signature takes nothing away from the account.
     *
     *      The ECDSA path rejects malleable signatures (upper-half s values) and
     *      invalid v values, and accepts only exactly 65 bytes. An existing
     *      authorization therefore cannot be rewritten into a second, differently
     *      encoded but equally valid signature.
     */
    function _requireValidSignature(address signer, bytes32 structHash, bytes memory signature)
        private
        view
    {
        bytes32 digest = _hashTypedDataV4(structHash);

        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == signer) return;

        if (SignatureChecker.isValidERC1271SignatureNow(signer, digest, signature)) return;

        revert InvalidAuthorizationSignature();
    }
}
