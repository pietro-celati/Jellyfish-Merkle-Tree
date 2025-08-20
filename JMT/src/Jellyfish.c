#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include "macros.h"

static uint64_t version = 0;
HashValue default_hash ={{0}};

typedef struct{
    uint64_t version;
    NibblePath nibble_path;
}NodeKey;

typedef struct{
    NodeKey leafKey;
    uint8_t* value;
    size_t valueLength;
    HashValue leafDigest;
} LeafNode; 

typedef struct{
    ChildNode* children[16];
}InternalNode;

typedef struct{
    uint8_t hash_bytes[32];
} HashValue;

typedef struct{
    uint8_t* nibbles;
    size_t length;
} NibblePath;

typedef struct{
    bool isLeaf;
    HashValue value;
    uint64_t version;
    union {
        struct InternalNode* internal;
        LeafNode* leaf;
    } node;
} ChildNode;

typedef struct Sibling{
    uint8_t index;
    HashValue hash; 
    struct Sibling* next;
} Sibling;

typedef struct LevelSibling{
    Sibling* siblings;
    struct LevelSibling* next;
} LevelSibling;

typedef struct{
    LevelSibling* levels;
    size_t depth;
    bool isPresent;
    HashValue leafHash;
} Proof;

HashValue computeInternalHash(InternalNode* node);
HashValue computeLeafHash(NodeKey* key, uint8_t* value, size_t len);
LeafNode* createLeafNode(NodeKey key, uint8_t* value, size_t len);
InternalNode* createInternalNode();
bool insertJMT(InternalNode** root, NodeKey* key, uint8_t* value, size_t len);
bool lookupJMT(InternalNode* root, NodeKey* key, uint8_t** result, size_t* length);
bool deleteJMT(InternalNode** root, NodeKey* key);
size_t longestCommonPrefix(const NibblePath* p1, const NibblePath* p2);
Sibling* createSiblingNode(uint8_t index, HashValue hash);
void addSibling(LevelSibling** level, uint8_t index, HashValue hash);
LevelSibling* addLevel(Proof* P);
bool generateMembershipProof(InternalNode* root, NodeKey* key, Proof *P);
bool verifyMembershipProof(NodeKey* key, Proof* P, HashValue rootDigest);
bool generateNonMembershipProof(InternalNode* root, NodeKey* key, Proof* P);
bool verifyNonMembershipProof(NodeKey* key, Proof* P, HashValue rootDigest);


int main(int argc, char** argv){
    
    return 0;
}





HashValue computeInternalHash(InternalNode* node) {
    SHA256_CTX sha256;

    uint8_t buffer[16 * sizeof(HashValue)];
    memset(buffer, 0, sizeof(buffer)); 

    for (size_t i = 0; i < 16; i++) {
        if (node->children[i] != NULL) {
            HashValue childHash;
            if (node->children[i]->isLeaf) {
                childHash = node->children[i]->node.leaf->leafDigest;
            } else {
                childHash = computeInternalHash(node->children[i]->node.internal);
            }
            memcpy(&buffer[i * sizeof(HashValue)], childHash.hash_bytes, sizeof(HashValue));
        }
    }

    // Singola operazione di hashing sull'intero buffer concatenato
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer, sizeof(buffer));
    
    HashValue h;
    SHA256_Final(h.hash_bytes, &sha256);
    free(buffer);
    return h;
}



HashValue computeLeafHash(NodeKey* key, uint8_t* value, size_t len){
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256,key,sizeof(NodeKey));
    SHA256_Update(&sha256,value,len);

    HashValue h;
    SHA256_Final(h.hash_bytes, &sha256);
    return h;
}

LeafNode* createLeafNode(NodeKey key, uint8_t* value, size_t len){
    LeafNode* leaf; 
    SYSCN(leaf,(LeafNode*)malloc(sizeof(LeafNode)),"Error allocating for leaf...");
    leaf->leafKey = key;
    SYSCN(leaf->value,(uint8_t*)malloc(len),"Error allocating for leaf value");
    memcpy(leaf->value, value, len);
    leaf->valueLength = len;
    leaf->leafDigest = computeLeafHash(&leaf->leafKey, leaf->value, leaf->valueLength);
    return leaf;
}

InternalNode* createInternalNode(){
    InternalNode* node; 
    SYCSN(node,(InternalNode*)malloc(sizeof(InternalNode)),"Error allocating for internal node...");
    memset(node->children, 0, sizeof(node->children));
    return node;
}

size_t longestCommonPrefix(const NibblePath* p1, const NibblePath* p2){
    size_t minLength = (p1->length < p2->length)? p1->length : p2->length;
    size_t lcp;
    for(lcp=0; lcp<minLength; lcp++){
        if(p1->nibbles[lcp] != p2->nibbles[lcp]) break;
    }
    return lcp;
}


bool insertJMT(InternalNode** root, NodeKey* key, uint8_t* value, size_t len) {
    if (key == NULL || value == NULL || len == 0) {
        fprintf(stderr, "Error: Invalid key or value in insert\n");
        return false;
    }

    NibblePath* path = &key->nibble_path;
    if (*root == NULL) *root = createInternalNode();

    InternalNode* current = *root;
    size_t depth = 0;

    while (depth < path->length) {
        uint8_t nextNibble = path->nibbles[depth];

        if (current->children[nextNibble] == NULL) {
            LeafNode* newLeaf = createLeafNode(*key, value, len);
            SYSCN(current->children[nextNibble], (ChildNode*)malloc(sizeof(ChildNode)),"Error allocating for childnode");
            current->children[nextNibble]->isLeaf = true;
            current->children[nextNibble]->node.leaf = newLeaf;
            return true;
        }

        ChildNode* child = current->children[nextNibble];

        if (child->isLeaf) {
            LeafNode* existingLeaf = child->node.leaf;
            NibblePath* existingPath = &existingLeaf->leafKey.nibble_path;
            size_t commonLen = longestCommonPrefix(path, existingPath);

            if (commonLen == path->length && commonLen == existingPath->length) {
                free(existingLeaf->value);
                SYSCN(existingLeaf->value, (uint8_t*)malloc(len), "Error allocating for value");
                memcpy(existingLeaf->value, value, len);
                existingLeaf->valueLength = len;
                existingLeaf->leafDigest = computeLeafHash(key, value, len);
                return true;
            } else {
                InternalNode* newInternal = createInternalNode();
                uint8_t existingNibble = existingPath->nibbles[commonLen];
                newInternal->children[existingNibble] = child;

                LeafNode* newLeaf = createLeafNode(*key, value, len);
                uint8_t newNibble = path->nibbles[commonLen];
                SYSCN(newInternal->children[newNibble], (ChildNode*)malloc(sizeof(ChildNode)),"Error allocating for childnode");
                newInternal->children[newNibble]->isLeaf = true;
                newInternal->children[newNibble]->node.leaf = newLeaf;

                SYSCN(current->children[nextNibble], (ChildNode*)malloc(sizeof(ChildNode)),"Error allocating for childnode");
                current->children[nextNibble]->isLeaf = false;
                current->children[nextNibble]->node.internal = newInternal;

                return true;
            }
        } else {
            current = child->node.internal;
            depth++;
        }
    }
    return false;
}


bool lookupJMT(InternalNode* root, NodeKey* key, uint8_t** result, size_t* resLength){
    if(root==NULL || key==NULL) return false;

    NibblePath* path = &key->nibble_path;
    InternalNode* current = root;
    size_t depth=0; 

    while(depth < path->length){
        uint8_t nextNibble = path->nibbles[depth];

        if(current->children[nextNibble]==NULL) return false;

        ChildNode* child = current->children[nextNibble];
        if(child->isLeaf){
            LeafNode* leaf = child->node.leaf;
            if(memcmp(&leaf->leafKey,key,sizeof(NodeKey))==0){
                *resLength = leaf->valueLength;
                *result = (uint8_t*)malloc(*resLength);
                memcpy(*result,leaf->value,*resLength);
                return true;
            } else return false;
        }
        else{
            current = child->node.internal;
            depth++;
        }
    }
    return false;
}

bool deleteJMT(InternalNode** root, NodeKey* key){
    if(*root==NULL || key==NULL) return false;

    NibblePath* path = &key->nibble_path;
    InternalNode* current = *root;
    size_t depth = 0;
    InternalNode* parent = NULL;
    uint8_t parentNibble = 0;


    while(depth < path->length){
        uint8_t nextNibble = path->nibbles[depth];
        if(current->children[nextNibble]==NULL) return false;

        parent = current;
        parentNibble = nextNibble;

        ChildNode* child = current->children[nextNibble];
        if(child->isLeaf){

            LeafNode* leaf = child->node.leaf;
            if(memcmp(&leaf->leafKey,key,sizeof(NodeKey)) == 0){
                free(leaf->value);
                free(leaf);
                free(child);
                parent->children[parentNibble] = NULL;

                size_t num_of_children = 0;
                size_t last_child_index = 0;
                for(size_t i=0; i<16; i++){
                    if(parent->children[i]!=NULL){
                        num_of_children++;
                        last_child_index=i;
                    }
                }
                if(num_of_children == 1){
                    ChildNode* lastChild = parent->children[last_child_index];
                    parent->children[last_child_index] = NULL;
                    
                    if(parent != *root){
                        current->children[parentNibble] = lastChild;
                    }
                    else{
                        *root = lastChild->node.internal;
                    }
                    free(parent);
                }
                return true;
            }
            else{
                return false; 
            }
        }
        else{
            current = child->node.internal;
            depth++;
        }
    }
    
    return false;
}

Sibling* createSiblingNode(uint8_t index, HashValue hash){
    Sibling* node;
    SYSCN(node, (Sibling*)malloc(sizeof(Sibling)),"Error allocating for sibling");

    node->index = index;
    node->hash = hash;
    node->next = NULL;
    return node;
}

void addSibling(LevelSibling** level, uint8_t index, HashValue hash){
    Sibling* newNode = createSiblingNode(index,hash);
    newNode->next = (*level)->siblings;
    (*level)->siblings = newNode;
    return;
}


LevelSibling* addLevel(Proof* P){
    LevelSibling* newLevel;
    SYSCN(newLevel,(LevelSibling*)malloc(sizeof(LevelSibling)),"Error allocating for level");

    newLevel->siblings = NULL;
    newLevel->next = P->levels;
    P->levels = newLevel;
    P->depth++;
    return newLevel;
}

bool generateMembershipProof(InternalNode* root, NodeKey* key, Proof *P){
    if(root==NULL || key==NULL || P==NULL) return false;
    
    NibblePath* path = &key->nibble_path;
    InternalNode* current = root;
    size_t depth = 0;
    P->depth = 0;
    P->levels = NULL;

    while(depth < path->length){
        uint8_t nextNibble = path->nibbles[depth];
        if(current->children[nextNibble]==NULL) return false;

        LevelSibling* level = addLevel(P);

        for(size_t i=0; i<16; i++){
            if(i!=nextNibble && current->children[i]!=NULL){
                HashValue siblingHash;
                
                if(current->children[i]->isLeaf){
                    siblingHash = current->children[i]->node.leaf->leafDigest;
                }
                else{
                    siblingHash = computeInternalHash(current->children[i]->node.internal);
                }
                addSibling(&level,i,siblingHash);
            }
        }

        ChildNode* child = current->children[nextNibble];
        if(child->isLeaf){
            LeafNode* leaf = child->node.leaf;
            if(memcmp(&leaf->leafKey,key,sizeof(NodeKey)) == 0){
                P->leafHash = leaf->leafDigest;
                P->isPresent = true;
                return true;
            } else return false;
        }
        else{
            current = child->node.internal;
            depth++;
        }

    }
    return false;
}


bool verifyMembershipProof(NodeKey* key, Proof* P, HashValue rootDigest) {
    if (P == NULL) return false;

    SHA256_CTX sha256;
    HashValue currentHash = P->leafHash;

    LevelSibling* level = P->levels;
    size_t depth = 0;

    while (level != NULL) {
        uint8_t buffer[16 * sizeof(HashValue)];
        memset(buffer, 0, sizeof(buffer));

        // Popolazione del buffer con gli hash dei fratelli
        Sibling* sibling = level->siblings;
        while (sibling != NULL) {
            size_t position = sibling->index * sizeof(HashValue);
            memcpy(&buffer[position], sibling->hash.hash_bytes, sizeof(HashValue));
            sibling = sibling->next;
        }

        // Inseriamo l'hash corrente nella posizione corretta (basata sul percorso di nibbles)
        uint8_t currentNibble = key->nibble_path.nibbles[depth];
        size_t currentPosition = currentNibble * sizeof(HashValue);
        memcpy(&buffer[currentPosition], currentHash.hash_bytes, sizeof(HashValue));

        // Calcolo dell'hash padre → Operazione unica su tutto il buffer concatenato
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, buffer, sizeof(buffer));
        SHA256_Final(currentHash.hash_bytes, &sha256);

        // Passaggio al livello successivo
        level = level->next;
        depth++;
    }

    // La prova è valida se l'hash finale corrisponde alla radice
    return memcmp(&currentHash, &rootDigest, sizeof(HashValue)) == 0;
}


bool generateNonMembershipProof(InternalNode* root, NodeKey* key, Proof* P){
    if(root==NULL || key==NULL || P==NULL) return false;

    NibblePath* path = &key->nibble_path;
    InternalNode* current = root; 
    size_t depth =0;
    P->depth = 0;
    P->levels = NULL;
    P->isPresent = false;

    while(depth < path->length){
        uint8_t nextNibble = path->nibbles[depth];
        LevelSibling* level = addLevel(P);

        for(size_t i=0; i<16; i++){
            if(i!=nextNibble && current->children[i]!=NULL){
                HashValue siblingHash; 
                if(current->children[i]->isLeaf){
                    siblingHash = current->children[i]->node.leaf->leafDigest;
                }else{
                    siblingHash = computeInternalHash(current->children[i]->node.internal);
                }
                addSibling(&level, i, siblingHash);
            }
        }

        ChildNode* child = current->children[nextNibble];
        if(child == NULL) return true;

        if(child->isLeaf){
            LeafNode* leaf = child->node.leaf;
            if(memcmp(&leaf->leafKey,key,sizeof(NodeKey)) != 0){
                P->leafHash = leaf->leafDigest;
                return true;
            } else return false;
        }
        else{
            current = child->node.internal;
            depth++;
        }
    }
    return true;
}



bool verifyNonMembershipProof(NodeKey* key, Proof *P, HashValue rootDigest){
    if(P==NULL) return false;

    SHA256_CTX sha256;
    HashValue currentHash = P->leafHash;

    LevelSibling* level = P->levels;
    size_t depth = 0;

    while(level!=NULL){
        uint8_t buffer[16*sizeof(HashValue)];
        memset(buffer,0,sizeof(buffer));

        Sibling* sibling = level->siblings;
        while(sibling != NULL){
            memcpy(&buffer[sibling->index*sizeof(HashValue)], sibling->hash.hash_bytes,sizeof(HashValue));
            sibling = sibling->next;
        }
        uint8_t nibble = key->nibble_path.nibbles[depth];
        memcpy(&buffer[nibble*sizeof(HashValue)], currentHash.hash_bytes, sizeof(HashValue));

        SHA256_Init(&sha256);
        SHA256_Update(&sha256, buffer, sizeof(buffer));
        SHA256_Final(currentHash.hash_bytes, &sha256);

        level = level->next;
        depth++;
    }

    return memcmp(&currentHash, &rootDigest, sizeof(HashValue)) == 0;
}
