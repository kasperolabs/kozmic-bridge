// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title TestToken: the asset the bridge locks while the loop is being proven out.
/// @notice Plain ERC-20, 6 decimals (so amounts look like USDC amounts), fixed supply
///         minted to the deployer at construction. No owner, no mint after that, no
///         pause. Nothing of value: it exists so the mainnet vault can be exercised
///         without locking real tokens forever.
contract TestToken {
    string public constant name = "Kaspero Bridge Test";
    string public constant symbol = "KBT";
    uint8 public constant decimals = 6;

    uint256 public immutable totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= value, "KBT: allowance");
            allowance[from][msg.sender] = allowed - value;
        }
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(to != address(0), "KBT: zero to");
        uint256 bal = balanceOf[from];
        require(bal >= value, "KBT: balance");
        balanceOf[from] = bal - value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
}
