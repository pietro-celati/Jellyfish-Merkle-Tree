#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include "keccak-tiny.h"
#include "macros.h"
#include "Jellyfish.h"
#define maxLev 64
#define MAX_TOKEN_ID 100000000
static uint32_t version = {0}; 
static uint32_t versionMap[MAX_TOKEN_ID] = {0};

HashValue default_hash ={{0}};
AncestryProof ancestryProof;

void printNibbles(const uint8_t* packed, size_t length) {
    printf("  nibble_path: ");
    for (size_t i = 0; i < length; i++) {
        printf("%X", getNibble(packed, i));
    }
    printf("\n");
}

NodeKey copyNodeKey(NodeKey original) {
    NodeKey copy = original;
    copy.nibble_path.nibbles = malloc(original.nibble_path.nibblesLength);
    memcpy(copy.nibble_path.nibbles, original.nibble_path.nibbles, original.nibble_path.nibblesLength);
    return copy;
}

Proof deepCopyProof(Proof* src) {
    Proof dst = {0};
    dst.leafHash = src->leafHash;
    dst.depth = src->depth;
    dst.isPresent = src->isPresent;

    LevelSibling* srcLvl = src->levels;
    LevelSibling** dstTail = &dst.levels;

    while (srcLvl) {
        LevelSibling* newLvl = malloc(sizeof(LevelSibling));
        newLvl->siblings = NULL;
        newLvl->next = NULL;

        Sibling** sTail = &newLvl->siblings;
        for (Sibling* s = srcLvl->siblings; s != NULL; s = s->next) {
            Sibling* newSib = malloc(sizeof(Sibling));
            newSib->index = s->index;
            newSib->hash = s->hash;
            newSib->next = NULL;
            *sTail = newSib;
            sTail = &newSib->next;
        }

        *dstTail = newLvl;
        dstTail = &newLvl->next;
        srcLvl = srcLvl->next;
    }

    return dst;
}

uint8_t getNibble(const uint8_t* packedNibbles, size_t index){
    return (index % 2 == 0) ? (packedNibbles[index / 2] >> 4) & 0x0F  :  packedNibbles[index / 2] & 0x0F;    
}


void setNibble(uint8_t* packedNibbles, size_t index, uint8_t val){
    if (index % 2 == 0) {
        packedNibbles[index / 2] = (packedNibbles[index / 2] & 0x0F) | (val << 4);
    } else {
        packedNibbles[index / 2] = (packedNibbles[index / 2] & 0xF0) | (val & 0x0F);
    }
}


HashValue computeInternalHash(InternalNode* node) {
    uint8_t buffer[16 * sizeof(HashValue)] = {0};
    HashValue h;

    for (size_t i = 0; i < 16; i++) {
        HashValue childHash;
        if (node->children[i] != NULL) {
            if (node->children[i]->isLeaf) {
                childHash = node->children[i]->node.leaf->leafDigest;
            } else {
                childHash = computeInternalHash(node->children[i]->node.internal);
            }
        } else {
            childHash = default_hash;  // <-- Assicura coerenza!
        }

        memcpy(&buffer[i * sizeof(HashValue)], childHash.hash_bytes, sizeof(HashValue));
    }

    keccak_256(h.hash_bytes, buffer, sizeof(buffer));
    return h;
}


HashValue computeProofRoot(NodeKey* key, Proof* P, HashValue leafStart) {
    HashValue current = leafStart;
    LevelSibling* level = P->levels;
    size_t depth = 0;

    if (!level) {
        uint8_t buffer[16 * sizeof(HashValue)];
        for (int i = 0; i < 16; i++) {
            memcpy(&buffer[i * sizeof(HashValue)], default_hash.hash_bytes, sizeof(HashValue));
        }
        uint8_t pos = getNibble(key->nibble_path.nibbles,P->depth-(depth+1));
        memcpy(&buffer[pos * sizeof(HashValue)], current.hash_bytes, sizeof(HashValue));

        keccak_256(current.hash_bytes, buffer, sizeof(buffer));
        return current;
    }

    while (level != NULL) {

            uint8_t buffer[16 * sizeof(HashValue)];
            for (int i = 0; i < 16; i++) {
                memcpy(&buffer[i * sizeof(HashValue)], default_hash.hash_bytes, sizeof(HashValue));
            }

            Sibling* S = level->siblings;
            while (S != NULL) {
                memcpy(&buffer[S->index * sizeof(HashValue)], S->hash.hash_bytes, sizeof(HashValue));
                S = S->next;
            }

            uint8_t pos = getNibble(key->nibble_path.nibbles, P->depth-(depth+1));
            memcpy(&buffer[pos * sizeof(HashValue)], current.hash_bytes, sizeof(HashValue));

            /*printf("  ➤ Buffer prima del keccak:\n");
            for (int i = 0; i < 16; i++) {
                printf("    [%02X]: ", i);
                for (int j = 0; j < 32; j++) {
                    printf("%02x", buffer[i * 32 + j]);
                }
                printf("\n");
            }*/

            keccak_256(current.hash_bytes, buffer, sizeof(buffer));
            /*printf("  ➤ Hash calcolato dopo il livello %zu: ", depth);
            printHash(current);
            printf("\n");*/

            level = level->next;
            depth++;
        }

    return current;
}

bool generateProof(InternalNode* root, NodeKey* key, Proof* P) {
    if (root == NULL || key == NULL || P == NULL) return false;

    NibblePath* path = &key->nibble_path;
    InternalNode* current = root;
    size_t depth = 0;
    P->depth = 0;
    P->levels = NULL;
    P->isPresent = false;

    while (depth < path->nibblesLength) {
        uint8_t nextNibble= getNibble(key->nibble_path.nibbles,depth);


        LevelSibling* level = addLevel(P);

        for (size_t i = 0; i < 16; i++) {
            if (i != nextNibble && current->children[i] != NULL) {
                HashValue siblingHash;
                if (current->children[i]->isLeaf) {
                    siblingHash = current->children[i]->node.leaf->leafDigest;
                } else {
                    siblingHash = computeInternalHash(current->children[i]->node.internal);
                }
                addSibling(&level, i, siblingHash);
            }
        }

        ChildNode* child = current->children[nextNibble];
        if (child == NULL) {
            // Prova di non inclusione: ramo vuoto
            return true;
        }

        if (child->isLeaf) {
            LeafNode* leaf = child->node.leaf;
            NibblePath* leafPath = &leaf->leafKey.nibble_path;

            if (leafPath->nibblesLength != path->nibblesLength) {
                // Prefisso divergente → esclusione
                P->leafHash = leaf->leafDigest;
                return true;
            }

            bool match = true;
            for (size_t i = 0; i < path->nibblesLength; i++) {
                if (getNibble(leafPath->nibbles, i) != getNibble(path->nibbles, i)) {
                    match = false;
                    break;
                }
            }

            if (match) {
                // Inclusione
                P->leafHash = leaf->leafDigest;
                P->isPresent = true;
                return true;
            } else {
                // Esclusione → foglia diversa
                P->leafHash = leaf->leafDigest;
                return true;
            }
        } else {
            current = child->node.internal;
            depth++;
        }
    }
    P->depth = depth;
    return true; // path completo senza trovare nulla → esclusione
}



HashValue computeLeafHash(NodeKey* key, uint8_t* value, size_t len){
    HashValue h;

    size_t tokenNibbles = key->nibble_path.nibblesLength - 8;  // esclude i primi 8 nibble = version
    uint8_t* expanded; 
    SYSCN(expanded, (uint8_t*)malloc(tokenNibbles), "Error allocating for temporary nibble buffer");

    for (size_t i = 0; i < tokenNibbles; i++) {
        expanded[i] = getNibble(key->nibble_path.nibbles, i + 8);  // skip i primi 8
    }

    size_t totalLen = tokenNibbles + len;
    uint8_t* input;
    SYSCN(input, (uint8_t*)malloc(totalLen), "Error allocating for keccak input");

    memcpy(input, expanded, tokenNibbles);
    memcpy(input + tokenNibbles, value, len);

    keccak_256(h.hash_bytes, input, totalLen);

    free(expanded);
    free(input);
    return h;
}

LeafNode* createLeafNode(NodeKey key, uint8_t* value, size_t len) {
    LeafNode* leaf;
    SYSCN(leaf, (LeafNode*)malloc(sizeof(LeafNode)), "Error allocating for leaf...");

    // Copia profonda della chiave
    leaf->leafKey.nibble_path.nibblesLength = key.nibble_path.nibblesLength;
    size_t byteLen = (key.nibble_path.nibblesLength + 1) / 2;
    SYSCN(leaf->leafKey.nibble_path.nibbles, (uint8_t*)malloc(byteLen), "Allocating leafKey.nibbles");
    memcpy(leaf->leafKey.nibble_path.nibbles, key.nibble_path.nibbles, byteLen);

    // Copia del valore
    SYSCN(leaf->value, (uint8_t*)malloc(len), "Error allocating for leaf value");
    memcpy(leaf->value, value, len);
    leaf->valueLength = len;

    // Calcolo hash della foglia
    leaf->leafDigest = computeLeafHash(&leaf->leafKey, leaf->value, leaf->valueLength);

    return leaf;
}


InternalNode* createInternalNode(){
    InternalNode* node; 
    SYSCN(node,(InternalNode*)malloc(sizeof(InternalNode)),"Error allocating for internal node...");
    memset(node->children, 0, sizeof(node->children));
    return node;
}

size_t longestCommonPrefix(const NibblePath* p1, const NibblePath* p2){
    size_t minLength = (p1->nibblesLength < p2->nibblesLength)? p1->nibblesLength : p2->nibblesLength;
    size_t lcp;
    for(lcp=0; lcp<minLength; lcp++){
        if(getNibble(p1->nibbles,lcp) != getNibble(p2->nibbles,lcp)) break;
    }
    return lcp;
}

bool lookupJMT(InternalNode* root, NodeKey* key, uint8_t** result, size_t* resLength){
    if(root==NULL || key==NULL) return false;

    NibblePath* path = &key->nibble_path;
    InternalNode* current = root;
    size_t depth=0; 

    while(depth < path->nibblesLength){
        uint8_t nextNibble = getNibble(path->nibbles, depth);
        if(current->children[nextNibble]==NULL) return false;

        ChildNode* child = current->children[nextNibble];
        if(child->isLeaf){
            LeafNode* leaf = child->node.leaf;
            NibblePath* leafPath = &leaf->leafKey.nibble_path;

            if(leafPath->nibblesLength == path->nibblesLength){
                bool match = true;
                for(size_t i=0; i<path->nibblesLength; i++){
                    if(getNibble(leafPath->nibbles,i) != getNibble(path->nibbles,i)) {match=false; break;}
                }
                if(match){
                    *resLength = leaf->valueLength;
                    SYSCN(*result,(uint8_t*)malloc(*resLength),"Error allocating for results");
                    memcpy(*result,leaf->value,*resLength);
                    return true;
                }
            }
            return false;
        }
        else{
            current = child->node.internal;
            depth++;
        }
    }
    return false;
}


bool insertJMT(InternalNode** root, NodeKey* key, uint8_t* value, size_t len,AncestryProof* ancestryOut) {
    if (key == NULL || value == NULL || len == 0) {
        fprintf(stderr, "Error: Invalid key or value in insert\n");
        return false;
    }

    NibblePath* path = &key->nibble_path;
    if (*root == NULL) *root = createInternalNode();

    InternalNode* current = *root;
    size_t depth = 0;

    while (depth < path->nibblesLength) {
        uint8_t nextNibble = getNibble(path->nibbles, depth);

        if (current->children[nextNibble] == NULL) {
            
            LeafNode* newLeaf = createLeafNode(*key, value, len);
            SYSCN(current->children[nextNibble], (ChildNode*)malloc(sizeof(ChildNode)),"Error allocating for childnode");
            current->children[nextNibble]->isLeaf = true;
            current->children[nextNibble]->node.leaf = newLeaf;

            ancestryOut->splitted = false;
            ancestryOut->key = *key;
            ancestryOut->RootN = computeInternalHash(*root);
            ancestryOut->preForkingDepth = 0;
            generateProof(*root, key, &ancestryOut->proof);

            return true;
        }

        ChildNode* child = current->children[nextNibble];

        if (child->isLeaf) {
            LeafNode* existingLeaf = child->node.leaf;
            NibblePath* existingPath = &existingLeaf->leafKey.nibble_path;
            size_t commonLen = longestCommonPrefix(path, existingPath);
        
            if (commonLen == path->nibblesLength && commonLen == existingPath->nibblesLength) {
                // Update existing leaf
                free(existingLeaf->value);
                SYSCN(existingLeaf->value, (uint8_t*)malloc(len), "Error allocating for value");
                memcpy(existingLeaf->value, value, len);
                existingLeaf->valueLength = len;
                existingLeaf->leafDigest = computeLeafHash(key, value, len);
                return true;
            } else {
                // Nuovo percorso di InternalNode da depth a commonLen - 1
                InternalNode* newBranch = createInternalNode();
                InternalNode* temp = newBranch;
        
                for (size_t i = depth+1; i < commonLen; i++) {
                    InternalNode* next = createInternalNode();
                    uint8_t nib = getNibble(existingPath->nibbles, i);
                    SYSCN(temp->children[nib], (ChildNode*)malloc(sizeof(ChildNode)), "Allocating mid internal child");
                    temp->children[nib]->isLeaf = false;
                    temp->children[nib]->node.internal = next;
                    temp = next;
                }
        
                // Inserisco entrambe le foglie
                uint8_t existingNibble = getNibble(existingPath->nibbles, commonLen);
                uint8_t newNibble = getNibble(path->nibbles, commonLen);
        
                SYSCN(temp->children[existingNibble], (ChildNode*)malloc(sizeof(ChildNode)), "Allocating for existing leaf");
                temp->children[existingNibble]->isLeaf = true;
                temp->children[existingNibble]->node.leaf = existingLeaf;
        
                LeafNode* newLeaf = createLeafNode(*key, value, len);
                SYSCN(temp->children[newNibble], (ChildNode*)malloc(sizeof(ChildNode)), "Allocating for new leaf");
                temp->children[newNibble]->isLeaf = true;
                temp->children[newNibble]->node.leaf = newLeaf;
        
                // Rimpiazzo la foglia con il nuovo ramo
                SYSCN(current->children[nextNibble], (ChildNode*)malloc(sizeof(ChildNode)), "Allocating for new branch");
                current->children[nextNibble]->isLeaf = false;
                current->children[nextNibble]->node.internal = newBranch;

                ancestryOut->splitted = true;
                ancestryOut->key = existingLeaf->leafKey;
                ancestryOut->preForkingDepth = depth+1;
                ancestryOut->RootN = computeInternalHash(*root);
                generateProof(*root, &ancestryOut->key, &ancestryOut->proof);

                return true;
            }
        }        
        else {
            current = child->node.internal;
            depth++;
        }
    }
    return false;
}


bool deleteJMT(InternalNode** root, NodeKey* key) {
    if (*root == NULL || key == NULL) return false;

    NibblePath* path = &key->nibble_path;
    InternalNode* current = *root;
    size_t depth = 0;

    InternalNode* parents[maxLev];
    uint8_t nibbles[maxLev];

    while (depth < path->nibblesLength) {
        uint8_t nibble = getNibble(path->nibbles, depth);
        if (current->children[nibble] == NULL) return false;

        // Salva info per la risalita
        parents[depth] = current;
        nibbles[depth] = nibble;

        ChildNode* child = current->children[nibble];

        if (child->isLeaf) {
            LeafNode* leaf = child->node.leaf;
            NibblePath* leafPath = &leaf->leafKey.nibble_path;

            // Verifica chiave
            if (leafPath->nibblesLength != path->nibblesLength) return false;
            for (size_t i = 0; i < path->nibblesLength; i++) {
                if (getNibble(leafPath->nibbles, i) != getNibble(path->nibbles, i)) return false;
            }

            // Libera risorse della foglia
            free(leaf->value);
            free(leaf);
            free(child);
            current->children[nibble] = NULL;

            // Risali lo stack per comprimere
            while (depth > 0) {
                depth--;
                InternalNode* parent = parents[depth];
                uint8_t pNibble = nibbles[depth];

                size_t count = 0;
                size_t lastIndex = 0;
                for (size_t i = 0; i < 16; i++) {
                    if (parent->children[i] != NULL) {
                        count++;
                        lastIndex = i;
                    }
                }

                if (count == 0) {
                    // Nodo vuoto, elimina
                    free(parent->children[pNibble]);
                    parent->children[pNibble] = NULL;
                } else if (count == 1) {
                    // Comprimibile: unico figlio → promozione se foglia
                    ChildNode* onlyChild = parent->children[lastIndex];
                    if (onlyChild->isLeaf) {
                        // Sostituisci questo internal node con la foglia
                        free(parent);
                        if (depth == 0) {
                            *root = NULL;
                        } else {
                            parents[depth - 1]->children[nibbles[depth - 1]] = onlyChild;
                        }
                    }
                    break;
                } else {
                    break;
                }
            }

            return true;
        }

        current = child->node.internal;
        depth++;
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


bool verifyProof(NodeKey* key, Proof* P, HashValue rootDigest) {
    if (P == NULL) return false;

    HashValue currentHash = P->leafHash;

    LevelSibling* level = P->levels;
    size_t depth = 0;

    while (level != NULL) {
        uint8_t buffer[16 * sizeof(HashValue)];
        memset(buffer, 0, sizeof(buffer));

        Sibling* sibling = level->siblings;
        while (sibling != NULL) {
            size_t position = sibling->index * sizeof(HashValue);
            memcpy(&buffer[position], sibling->hash.hash_bytes, sizeof(HashValue));
            sibling = sibling->next;
        }

        uint8_t currentNibble = getNibble(key->nibble_path.nibbles, depth);
        size_t currentPosition = currentNibble * sizeof(HashValue);
        memcpy(&buffer[currentPosition], currentHash.hash_bytes, sizeof(HashValue));

        keccak_256(currentHash.hash_bytes, buffer, sizeof(buffer));

        level = level->next;
        depth++;
    }

    return memcmp(&currentHash, &rootDigest, sizeof(HashValue)) == 0;
}


NodeKey buildKey(NibblePath tokenPath) {
    uint32_t versionNum = version++;
    NodeKey key;

    size_t totalNibbles = 8 + tokenPath.nibblesLength;
    size_t totalBytes = (totalNibbles + 1) / 2;

    SYSCN(key.nibble_path.nibbles, (uint8_t*)calloc(totalBytes, sizeof(uint8_t)), "Error allocating for key");
    key.nibble_path.nibblesLength = totalNibbles;

    for (size_t i = 0; i < 4; i++) {
        uint8_t byte = (versionNum >> (8 * (3 - i))) & 0xFF;
        setNibble(key.nibble_path.nibbles, i * 2,     (byte >> 4) & 0x0F);
        setNibble(key.nibble_path.nibbles, i * 2 + 1,  byte & 0x0F);
    }

    for (size_t j = 0; j < tokenPath.nibblesLength; j++) {
        setNibble(key.nibble_path.nibbles, j + 8, getNibble(tokenPath.nibbles, j));
    }

    return key;
}

NibblePath buildPathFromTokenId(uint64_t tokenId){
    NibblePath p;
    p.nibblesLength = 16;
    SYSCN(p.nibbles, (uint8_t*)calloc((p.nibblesLength + 1) / 2, sizeof(uint8_t)), "Error allocating TokenPath");

    for (int i = 0; i < 8; i++) {
        uint8_t byte = (tokenId >> (8 * (7 - i))) & 0xFF;
        setNibble(p.nibbles, i * 2,     (byte >> 4) & 0x0F);
        setNibble(p.nibbles, i * 2 + 1,  byte & 0x0F);
    }

    return p;
}

LevelSibling* truncateProofLevels(LevelSibling* head, size_t keepDepth) {
    size_t depth = 0;
    LevelSibling* current = head;
    LevelSibling* prev = NULL;

    while (current && depth < keepDepth) {
        prev = current;
        current = current->next;
        depth++;
    }

    if (prev) {
        prev->next = NULL;  // Tronca la lista
    }

    return head;
}


HashValue prevRootJMT(AncestryProof* ancestry, uint8_t* insertedValue, size_t insertedValueLen) {
    if (!ancestry || !insertedValue || insertedValueLen == 0) return default_hash;
    if (ancestry->proof.levels == NULL) {
        printf("❌ ERRORE: proof.levels è NULL in prevRootJMT con splitted==true\n");
        return default_hash;
    }
    printf("🔢 preForkingDepth = %zu\n", ancestry->preForkingDepth);

    if (ancestry->preForkingDepth == 0) {
    // Simula una root contenente solo default hash
        return computeProofRoot(&ancestry->key, &ancestry->proof, ancestry->proof.leafHash);
    }



    if (!ancestry->splitted) {
        HashValue insertedHash = computeLeafHash(&ancestry->key, insertedValue, insertedValueLen);
        HashValue rootCheck = computeProofRoot(&ancestry->key, &ancestry->proof, insertedHash);
        printf("RootCheck="); printHash(rootCheck);
        printf("\nRootN="); printHash(ancestry->RootN);
        printf("\n");
        if (memcmp(rootCheck.hash_bytes, ancestry->RootN.hash_bytes, sizeof(HashValue)) != 0) {
            printf("Ho ragione!\n");
            return default_hash;
        }
        return computeProofRoot(&ancestry->key, &ancestry->proof, default_hash);
    }

    HashValue rootCheck = computeProofRoot(&ancestry->key, &ancestry->proof, ancestry->proof.leafHash);
    if (memcmp(rootCheck.hash_bytes, ancestry->RootN.hash_bytes, sizeof(HashValue)) != 0) {
        return default_hash;
    }

    // Troncamento della proof
    Proof truncatedProof = {0};
    LevelSibling* full = ancestry->proof.levels;
    LevelSibling** tail = &truncatedProof.levels;
    size_t currentDepth = 0;

    while (full != NULL && currentDepth < ancestry->preForkingDepth) {
        LevelSibling* copy;
        SYSCN(copy, (LevelSibling*)malloc(sizeof(LevelSibling)), "Allocating truncated level");
        copy->siblings = NULL;
        copy->next = NULL;

        Sibling* s = full->siblings;
        Sibling** sTail = &copy->siblings;
        while (s != NULL) {
            Sibling* sCopy;
            SYSCN(sCopy, (Sibling*)malloc(sizeof(Sibling)), "Allocating sibling copy");
            sCopy->index = s->index;
            sCopy->hash = s->hash;
            sCopy->next = NULL;
            *sTail = sCopy;
            sTail = &sCopy->next;
            s = s->next;
        }

        *tail = copy;
        tail = &copy->next;
        full = full->next;
        currentDepth++;
    }

    truncatedProof.leafHash = ancestry->proof.leafHash;
    truncatedProof.depth = ancestry->preForkingDepth;
    truncatedProof.isPresent = true;

    return computeProofRoot(&ancestry->key, &truncatedProof, ancestry->proof.leafHash);
}


void printIndent(int level) {
    for (int i = 0; i < level; i++) printf("  ");
}

void printHash(HashValue h) {
    for (int i = 0; i < 32; i++) printf("%02x", h.hash_bytes[i]);
}

void printJMT(InternalNode* node, int depth, char* prefix, bool isLast) {
    if (!node) return;

    char newPrefix[512];
    if (depth == 0) {
        strcpy(newPrefix, "");
    } else {
        strcpy(newPrefix, prefix);
        strcat(newPrefix, isLast ? "    " : "│   ");
    }

    for (int i = 0; i < 16; i++) {
        ChildNode* child = node->children[i];
        if (!child) continue;

        bool lastChild = true;
        for (int j = i + 1; j < 16; j++) {
            if (node->children[j]) {
                lastChild = false;
                break;
            }
        }

        printf("%s%s Nibble [%X]: ", prefix, lastChild ? "└──" : "├──", i);
        if (child->isLeaf) {
            LeafNode* leaf = child->node.leaf;
            printf("Leaf → hash: ");
            printHash(leaf->leafDigest);
            printf(" | value: %.*s\n", (int)leaf->valueLength, leaf->value);
        } else {
            InternalNode* internal = child->node.internal;
            printf("Internal → hash: ");
            printHash(computeInternalHash(internal));
            printf("\n");
            printJMT(internal, depth + 1, newPrefix, lastChild);
        }
    }
}


void printProof(Proof* P) {
    printf("📜 PROOF:\n");
    if (!P || !P->levels) {
        printf("  (vuota o nulla)\n");
        return;
    }

    LevelSibling* level = P->levels;
    size_t depth = 0;
    while (level != NULL) {
        printf("🔸 Livello %zu:\n", depth);
        Sibling* s = level->siblings;
        while (s != NULL) {
            printf("    ➤ index = %u | hash = ", s->index);
            printHash(s->hash);
            printf("\n");
            s = s->next;
        }
        level = level->next;
        depth++;
    }
    printf("🔚 Fine proof\n");
}

NodeKey buildKeyWithControl(uint64_t tokenId, bool isMint) {
    NibblePath tokenPath = buildPathFromTokenId(tokenId);

    uint32_t versionNum;
    if (isMint) {
        versionNum = version++;
        if (tokenId < MAX_TOKEN_ID)
            versionMap[tokenId] = versionNum;
    } else {
        if (tokenId >= MAX_TOKEN_ID) {
            fprintf(stderr, "❌ Token ID troppo grande per versionMap: %lu\n", tokenId);
            exit(EXIT_FAILURE);
        }
        versionNum = versionMap[tokenId];
    }

    NodeKey key;
    size_t totalNibbles = 8 + tokenPath.nibblesLength;
    size_t totalBytes = (totalNibbles + 1) / 2;

    SYSCN(key.nibble_path.nibbles, (uint8_t*)calloc(totalBytes, sizeof(uint8_t)), "Error allocating for key");
    key.nibble_path.nibblesLength = totalNibbles;

    for (size_t i = 0; i < 4; i++) {
        uint8_t byte = (versionNum >> (8 * (3 - i))) & 0xFF;
        setNibble(key.nibble_path.nibbles, i * 2,     (byte >> 4) & 0x0F);
        setNibble(key.nibble_path.nibbles, i * 2 + 1,  byte & 0x0F);
    }

    for (size_t j = 0; j < tokenPath.nibblesLength; j++) {
        setNibble(key.nibble_path.nibbles, j + 8, getNibble(tokenPath.nibbles, j));
    }

    free(tokenPath.nibbles);
    return key;
}


