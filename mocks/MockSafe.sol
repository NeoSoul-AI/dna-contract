// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @dev Fake Safe for testing; it only provides the three view functions that checkSafe calls.
///      Not deployed to any production network.
contract MockSafe {
    address[] private _owners;
    uint256 private _threshold;

    constructor(address[] memory owners_, uint256 threshold_) {
        _owners = owners_;
        _threshold = threshold_;
    }

    function getOwners() external view returns (address[] memory) { return _owners; }
    function getThreshold() external view returns (uint256) { return _threshold; }
    function VERSION() external pure returns (string memory) { return "1.4.1"; }
}
