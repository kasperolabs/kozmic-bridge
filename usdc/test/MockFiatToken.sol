// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice A minimal stand-in for Circle's FiatTokenV2_2 for unit tests: 6 decimals, a blacklister, and the
///         same rule that matters to the vault: `transfer` and `transferFrom` revert when either side is
///         blacklisted. The storage layout is NOT USDC's (the fork tests cover that); only the behaviour is.
contract MockFiatToken {
    string public constant name = "Mock USD Coin";
    string public constant symbol = "mUSDC";
    uint8 public constant decimals = 6;
    address public blacklister;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public isBlacklisted;

    constructor() {
        blacklister = msg.sender;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function blacklist(address a) external {
        require(msg.sender == blacklister, "not blacklister");
        isBlacklisted[a] = true;
    }

    function unBlacklist(address a) external {
        require(msg.sender == blacklister, "not blacklister");
        isBlacklisted[a] = false;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(!isBlacklisted[msg.sender] && !isBlacklisted[to], "Blacklistable: account is blacklisted");
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(!isBlacklisted[msg.sender] && !isBlacklisted[from] && !isBlacklisted[to], "Blacklistable: account is blacklisted");
        require(allowance[from][msg.sender] >= amount, "ERC20: transfer amount exceeds allowance");
        allowance[from][msg.sender] -= amount;
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "ERC20: transfer amount exceeds balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}
