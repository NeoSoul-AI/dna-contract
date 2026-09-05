// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @dev EIP-1271 contract wallet for testing; its behaviour mimics a 1-of-1 Gnosis Safe:
 *      it delegates verification to the signature of a single owner EOA.
 *      Used only in tests; it is not deployed to any production network.
 */
contract MockERC1271Signer {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;

    address public immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) {
            return MAGIC_VALUE;
        }
        return 0xffffffff;
    }
}
