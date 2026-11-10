// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DegenNFT
/// @notice Legitimate unverified ERC-721 NFT contract with standard public minting.
/// @dev Used to prove SafeGuard allows autonomous agent mints without human friction in degen mode.
contract DegenNFT {
    string public name = "Degen Early Adopter";
    string public symbol = "DEGEN";
    uint256 public constant MINT_PRICE = 0.05 ether;
    uint256 public totalSupply;

    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    function mint(uint256 quantity) external payable {
        require(msg.value >= MINT_PRICE * quantity, "Insufficient ETH sent for mint");
        for (uint256 i = 0; i < quantity; i++) {
            uint256 tokenId = ++totalSupply;
            ownerOf[tokenId] = msg.sender;
            balanceOf[msg.sender]++;
            emit Transfer(address(0), msg.sender, tokenId);
        }
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }
}

