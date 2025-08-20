#ifndef JELLYFISH_STRUCTURE_H
#define JELLYFISH_STRUCTURE_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#define HASH_SIZE 32


typedef struct {
    uint8_t hash_bytes[HASH_SIZE];
} HashValue;

typedef struct {
    uint8_t* nibbles;
    size_t nibblesLength;
} NibblePath;

typedef struct {
    uint32_t version;
    NibblePath nibble_path;
} NodeKey;

typedef struct {
    NodeKey leafKey;
    uint8_t* value;
    size_t valueLength;
    HashValue leafDigest;
} LeafNode;

typedef struct InternalNode InternalNode;

typedef struct ChildNode {
    bool isLeaf;
    union {
        LeafNode* leaf;
        InternalNode* internal;
    } node;
} ChildNode;

struct InternalNode {
    ChildNode* children[16];
};

typedef struct Sibling {
    uint8_t index;
    HashValue hash;
    struct Sibling* next;
} Sibling;

typedef struct LevelSibling {
    Sibling* siblings;
    struct LevelSibling* next;
} LevelSibling;

typedef struct {
    bool isPresent;
    size_t depth;
    LevelSibling* levels;
    HashValue leafHash;
} Proof;

typedef struct {
    bool splitted;
    size_t preForkingDepth;
    NodeKey key;
    Proof proof;
    HashValue RootN;
} AncestryProof;

// Funzioni principali da esportare
NibblePath buildPathFromTokenId(uint64_t tokenId);
InternalNode* createInternalNode();
LeafNode* createLeafNode(NodeKey key, uint8_t* value, size_t len);
bool lookupJMT(InternalNode* root, NodeKey* key, uint8_t** result, size_t* resLength);
bool insertJMT(InternalNode** root, NodeKey* key, uint8_t* value, size_t len,AncestryProof* ap) ;
bool deleteJMT(InternalNode** root, NodeKey* key) ;
HashValue computeLeafHash(NodeKey* key, uint8_t* value, size_t len);
HashValue computeInternalHash(InternalNode* node) ;
HashValue computeProofRoot(NodeKey* key, Proof* P, HashValue leafStart);
bool generateProof(InternalNode* root, NodeKey* key, Proof* P);
size_t longestCommonPrefix(const NibblePath* p1, const NibblePath* p2);

// Utility
void printHash(HashValue h);
void printNibbles(const uint8_t* packed, size_t length);
Proof deepCopyProof(Proof* src);
NodeKey copyNodeKey(NodeKey original) ;
uint8_t getNibble(const uint8_t* packedNibbles, size_t index);
void setNibble(uint8_t* packedNibbles, size_t index, uint8_t val);
Sibling* createSiblingNode(uint8_t index, HashValue hash);
void addSibling(LevelSibling** level, uint8_t index, HashValue hash);
LevelSibling* addLevel(Proof* P);
bool verifyProof(NodeKey* key, Proof* P, HashValue rootDigest);
NodeKey buildKey(NibblePath tokenPath);
NibblePath buildPathFromTokenId(uint64_t tokenId);
LevelSibling* truncateProofLevels(LevelSibling* head, size_t keepDepth);
HashValue prevRootJMT(AncestryProof* ancestry, uint8_t* insertedValue, size_t insertedValueLen);
void printIndent(int level);
void printHash(HashValue h);
void printJMT(InternalNode* node, int depth, char* prefix, bool isLast);
void printProof(Proof* P);
NodeKey buildKeyWithControl(uint64_t tokenId, bool isMint);
#endif // JELLYFISH_STRUCTURE_H
