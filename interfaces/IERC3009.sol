// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title IERC3009
 * @notice External interface for EIP-3009, for use by integrating contracts (USDC and others
 *         implement the same set of signatures).
 * @dev Both signature formats are listed: (v,r,s) is the form from the original specification,
 *      while the bytes version additionally supports EIP-1271 contract wallets.
 */
interface IERC3009 {
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
    ) external;

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
    ) external;

    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external;

    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)
        external;

    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);
}
