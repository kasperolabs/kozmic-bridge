// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice A mintable test token with USDC's storage layout for exactly what the inbound guest reads:
///         `balanceAndBlacklistStates` at mapping slot 9 (flag = bit 255, balance = low 255 bits) and the
///         ZeppelinOS implementation slot `keccak256("org.zeppelinos.proxy.implementation")` holding Circle's
///         real implementation address (`0x43506849…02dd`), so the covenant constant is the same as on the real
///         instance. Transfers revert when either side is blacklisted, as FiatTokenV2_2 does. For U3's dev-mode
///         runs on mainnet data only; U5's rehearsal deploys Circle's actual FiatToken code.
contract MockUsdcLayout {
    bytes32 private constant IMPL_SLOT = 0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3;
    address private constant USDC_IMPLEMENTATION = 0x43506849D7C04F9138D1A2050bbF3A0c054402dd;
    uint256 private constant FLAG = 1 << 255;

    // slots 0..8: placeholders so the mapping below is slot 9, as in FiatTokenV2_2
    uint256 private s0; uint256 private s1; uint256 private s2; uint256 private s3; uint256 private s4;
    uint256 private s5; uint256 private s6; uint256 private s7; uint256 private s8;
    mapping(address => uint256) private balanceAndBlacklistStates; // slot 9
    mapping(address => mapping(address => uint256)) public allowance; // slot 10
    address public blacklister;

    string public constant name = "Kaspero Layout Test Dollar";
    string public constant symbol = "KLTD";
    uint8 public constant decimals = 6;

    constructor() {
        blacklister = msg.sender;
        assembly { sstore(IMPL_SLOT, USDC_IMPLEMENTATION) }
    }

    function balanceOf(address a) public view returns (uint256) { return balanceAndBlacklistStates[a] & ~FLAG; }
    function isBlacklisted(address a) public view returns (bool) { return balanceAndBlacklistStates[a] >> 255 == 1; }

    function mint(address to, uint256 amount) external {
        _set(to, balanceOf(to) + amount);
    }

    function blacklist(address a) external {
        require(msg.sender == blacklister, "not blacklister");
        balanceAndBlacklistStates[a] |= FLAG;
    }

    function unBlacklist(address a) external {
        require(msg.sender == blacklister, "not blacklister");
        balanceAndBlacklistStates[a] &= ~FLAG;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(!isBlacklisted(msg.sender) && !isBlacklisted(to), "Blacklistable: account is blacklisted");
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(!isBlacklisted(msg.sender) && !isBlacklisted(from) && !isBlacklisted(to), "Blacklistable: account is blacklisted");
        require(allowance[from][msg.sender] >= amount, "ERC20: transfer amount exceeds allowance");
        allowance[from][msg.sender] -= amount;
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) internal {
        require(balanceOf(from) >= amount, "ERC20: transfer amount exceeds balance");
        _set(from, balanceOf(from) - amount);
        _set(to, balanceOf(to) + amount);
    }

    function _set(address a, uint256 balance) internal {
        require(balance < FLAG, "balance too large");
        balanceAndBlacklistStates[a] = (balanceAndBlacklistStates[a] & FLAG) | balance;
    }
}
