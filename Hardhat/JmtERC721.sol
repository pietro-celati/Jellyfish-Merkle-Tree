// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "hardhat/console.sol";


event DebugBytes32(string label, bytes32 value);
event DebugUint(string label, uint256 value);
event DebugBytes(string label, bytes value);

contract JmtERC721 is ERC721 {
    address public immutable creator;
    bytes32 public jmtRoot = 0;
    uint256 public lastTokenId;
    uint256 public numTokens = 0;

    constructor(string memory name, string memory symbol) ERC721(name, symbol) {
        creator = msg.sender;

        bytes32[16] memory buffer;
        for (uint i = 0; i < 16; i++) {
            buffer[i] = bytes32(0);
        }
        jmtRoot = keccak256(abi.encodePacked(
            buffer[0], buffer[1], buffer[2], buffer[3],
            buffer[4], buffer[5], buffer[6], buffer[7],
            buffer[8], buffer[9], buffer[10], buffer[11],
            buffer[12], buffer[13], buffer[14], buffer[15]
        ));
    }

    struct Sibling {
        uint8 index;
        bytes32 hash;
    }

    struct LevelSibling {
        Sibling[] siblings;
    }

    struct Proof {
        bool isMembership;
        LevelSibling[] levels;
        uint256 depth;
        uint256 tokenId;
        bytes32 leafHash;
        bytes32 root;
    }

    struct AncestryProof {
        bool splitted;
        uint256 preForkDepth;
        Proof P;
        uint256 tokenId;
        uint32 version;
    }

    function publicVerify(
        Proof calldata P,
        uint256 tokenId,
        uint32 version,
        bytes calldata value
    ) external returns (bool) {
        return verify(P, tokenId, version, value);
    }


    function verify(Proof calldata P, uint256 tokenId, uint32 version, bytes calldata value) internal
     view returns (bool valid) {
        require(P.depth == P.levels.length, "Depth mismatch");
        require(P.tokenId == tokenId, "TokenId mismatch");

        bytes memory input = new bytes(16 + value.length);
        for (uint i = 0; i < 8; i++) {
            uint8 byteVal = uint8(tokenId >> (8 * (7 - i)));
            input[2 * i]     = bytes1(byteVal >> 4);
            input[2 * i + 1] = bytes1(byteVal & 0x0F);
        }
        for (uint j = 0; j < value.length; j++) {
            input[16 + j] = value[j];
        }

        bytes32 expectedLeaf = keccak256(input);

        bool membershipValid = (
            (P.isMembership && (P.leafHash == expectedLeaf)) ||
            (!P.isMembership && (P.leafHash != expectedLeaf))
        );

        uint256 fullKey = (uint256(version) << 64) | tokenId;
        valid = (P.root == jmtRoot) && _verifyProof(P, fullKey) && membershipValid;
    }


    function _verifyProof(Proof calldata P, uint256 fullKey) internal pure returns (bool valid) {
        bytes32 currentHash = P.leafHash;
        for (uint256 levelIdx = 0; levelIdx < P.levels.length; levelIdx++) {
            uint8 nibble = _getNibble(fullKey, P.depth-(levelIdx));
            currentHash = _computeLevelHash(P.levels[levelIdx], currentHash, nibble);
        }
        valid = (currentHash == P.root);
    }

    function _getNibble(uint256 fullKey, uint256 depth) internal pure returns (uint8) {
        // Legge i nibble da sinistra verso destra su 24 nibble (da bit 92 a bit 0)
        return uint8((fullKey >> (4 * (24 - depth))) & 0x0F);
    }



    function mint(
        uint256 tokenId,
        uint32 version,
        bytes calldata value,
        Proof calldata proofNew,
        AncestryProof calldata ancestryProof
    ) external {
        bytes memory input = new bytes(16 + value.length);
        for (uint i = 0; i < 8; i++) {
            uint8 byteVal = uint8(tokenId >> (8 * (7 - i)));
            input[2 * i]     = bytes1(byteVal >> 4);
            input[2 * i + 1] = bytes1(byteVal & 0x0F);
        }
        for (uint j = 0; j < value.length; j++) {
            input[16 + j] = value[j];
        }
        require(proofNew.leafHash == keccak256(input), "Invalid leaf hash");

        uint256 fullKey = (uint256(version) << 64) | tokenId;
        uint256 fullKeyAncestry = (uint256(ancestryProof.version) << 64) | ancestryProof.tokenId;

        bytes32 rootFromMembership = _computeRootFromProof(proofNew, proofNew.leafHash, fullKey);
        bytes32 rootFromAncestry = _computeRootFromProof(ancestryProof.P, ancestryProof.P.leafHash, fullKeyAncestry);
        require(rootFromAncestry == rootFromMembership, "Inconsistent proofs");

        bytes32 prevRoot = _computePrevRootJMT(ancestryProof, fullKeyAncestry);
        require(prevRoot == jmtRoot, "Previous root mismatch");

        _safeMint(msg.sender, tokenId);
        jmtRoot = rootFromAncestry;
        lastTokenId = tokenId;
        numTokens += 1;
    }

    function _computeRootFromProof(Proof calldata P, bytes32 leafDigest, uint256 fullKey) internal pure returns (bytes32 root) {
        bytes32 currentHash = leafDigest;
        for (uint256 levelIdx = 0; levelIdx < P.levels.length; levelIdx++) {
            uint8 nibble = _getNibble(fullKey, P.depth-(levelIdx));
            currentHash = _computeLevelHash(P.levels[levelIdx], currentHash, nibble);
        }
        return currentHash;
    }

    function _computeLevelHash(LevelSibling calldata level, bytes32 currentHash, uint8 nibble)
        internal
        pure
        returns (bytes32 newHash)
    {
        bytes32[16] memory buffer;

        for (uint256 j = 0; j < level.siblings.length; j++) {
            uint8 idx = level.siblings[j].index;
            buffer[idx] = level.siblings[j].hash;
        }

        buffer[nibble] = currentHash;

        newHash = keccak256(abi.encodePacked(
            buffer[0], buffer[1], buffer[2], buffer[3],
            buffer[4], buffer[5], buffer[6], buffer[7],
            buffer[8], buffer[9], buffer[10], buffer[11],
            buffer[12], buffer[13], buffer[14], buffer[15]
        ));
    }

    function _computePrevRootJMT(AncestryProof calldata AP, uint256 fullKey) internal pure returns (bytes32 prevRoot) {
        if (!AP.splitted) {
            return _computeRootFromProof(AP.P, bytes32(0), fullKey);
        }

        bytes32 currentHash = AP.P.leafHash;
        for (uint256 i = (AP.P.depth-AP.preForkDepth); i < AP.P.depth; i++) {
            uint8 nibble = _getNibble(fullKey, AP.P.depth-i);
            currentHash = _computeLevelHash(AP.P.levels[i], currentHash, nibble);
        }

        return currentHash;
    }

    function computePrevRoot(
        AncestryProof calldata ancestry
    ) external pure returns (bytes32) {
        uint256 fullKey = (uint256(ancestry.version) << 64) | ancestry.tokenId;

        if (!ancestry.splitted) {
            return _computeRootFromProof(ancestry.P, bytes32(0), fullKey);
        }

        bytes32 currentHash = ancestry.P.leafHash;
        for (uint256 i = (ancestry.P.depth - ancestry.preForkDepth); i < ancestry.P.depth; i++) {
            uint8 nibble = _getNibble(fullKey, ancestry.P.depth - i);
            currentHash = _computeLevelHash(ancestry.P.levels[i], currentHash, nibble);
        }

        return currentHash;
    }


    function computeRootFromProof(
        uint256 tokenId,
        uint32 version,
        bytes32 leafHash,
        LevelSibling[] calldata levels,
        uint32 depth
    ) external pure returns (bytes32 root) {
        bytes32 currentHash = leafHash;
        uint256 fullKey = (uint256(version) << 64) | tokenId;
        for (uint256 levelIdx = 0; levelIdx < levels.length; levelIdx++) {
            uint8 nibble = _getNibble(fullKey, depth -levelIdx);
            currentHash = _computeLevelHash(levels[levelIdx], currentHash, nibble);
        }
        return currentHash;
    }

    function computeLevelHashExternal(LevelSibling calldata level, bytes32 currentHash, uint8 nibble)
        external
        pure
        returns (bytes32)
    {
        bytes32[16] memory buffer;

        for (uint256 j = 0; j < level.siblings.length; j++) {
            uint8 idx = level.siblings[j].index;
            buffer[idx] = level.siblings[j].hash;
        }

        buffer[nibble] = currentHash;

        return keccak256(abi.encodePacked(
            buffer[0], buffer[1], buffer[2], buffer[3],
            buffer[4], buffer[5], buffer[6], buffer[7],
            buffer[8], buffer[9], buffer[10], buffer[11],
            buffer[12], buffer[13], buffer[14], buffer[15]
        ));
    }

    function debugFullKey(uint32 version, uint256 tokenId) external pure returns (uint256 fullKey) {
        fullKey = (uint256(version) << 64) | tokenId;

        console.log("version:", version);
        console.log("tokenId:", tokenId);
        console.log("fullKey:", fullKey);
        console.logBytes32(bytes32(fullKey));
    }

}

