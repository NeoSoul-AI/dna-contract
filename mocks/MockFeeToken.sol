// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @dev For testing: a token that charges a 2% fee on every transfer.
 *      Used to verify that TokenVesting measures "how much was actually received" instead of
 *      "trusting the parameter" — DeNeoAgent itself has no transfer fee, but this contract may be
 *      used to lock other tokens.
 *      Used only in tests.
 */
contract MockFeeToken is ERC20 {
    uint256 public constant FEE_BPS = 200; // 2%

    constructor(address holder, uint256 supply) ERC20("Fee Token", "FEE") {
        _mint(holder, supply);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from == address(0) || to == address(0)) {
            super._update(from, to, value);
            return;
        }
        uint256 fee = (value * FEE_BPS) / 10_000;
        super._update(from, to, value - fee);
        if (fee > 0) super._update(from, address(0xdead), fee);
    }
}
