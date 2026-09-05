// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC3009} from "../interfaces/IERC3009.sol";

/**
 * @dev ⚠️ DELIBERATELY VULNERABLE COUNTER-EXAMPLE — FOR TESTING ONLY. NEVER DEPLOY THIS.
 *
 *      This version makes two textbook mistakes, and the tests actually reproduce the attacks:
 *
 *      1. It uses transferWithAuthorization instead of receiveWithAuthorization
 *         → an attacker can front-run it by submitting the authorization on its own, consuming the
 *           nonce and making this function revert, so the buyer's money ends up in the vault while
 *           the buyer never receives the goods.
 *
 *      2. It delivers the goods to msg.sender instead of to the `from` in the authorization
 *         → in relayer mode, whoever submits the transaction walks away with the goods.
 */
contract NaiveVault {
    using SafeERC20 for IERC20;

    IERC20 public immutable payToken;
    IERC20 public immutable goodsToken;
    uint256 public immutable rate;

    constructor(address payToken_, address goodsToken_, uint256 rate_) {
        payToken = IERC20(payToken_);
        goodsToken = IERC20(goodsToken_);
        rate = rate_;
    }

    /// @dev Mistake 1: transferWithAuthorization can be called by anyone
    function buyVulnerable(
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        IERC3009(address(payToken)).transferWithAuthorization(
            from, address(this), value, validAfter, validBefore, nonce, v, r, s
        );
        goodsToken.safeTransfer(from, (value * rate) / 1e18);
    }

    /// @dev Mistake 2: delivers to msg.sender
    function buyCreditsWrongAccount(
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external {
        IERC3009(address(payToken)).receiveWithAuthorization(
            from, address(this), value, validAfter, validBefore, nonce, signature
        );
        // ← this line is wrong: the payer is `from`, not msg.sender
        goodsToken.safeTransfer(msg.sender, (value * rate) / 1e18);
    }
}
