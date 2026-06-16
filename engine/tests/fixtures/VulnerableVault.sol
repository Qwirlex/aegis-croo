// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;
contract VulnerableVault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");   // reentrancy: external call before state update
        require(ok);
        balances[msg.sender] = 0;
    }
}
