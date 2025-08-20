#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "Jellyfish.h"
#include <sys/stat.h>
#include <sys/types.h>

AncestryProof ancestryP;
#define MAX_TOKEN_ID 10000000

uint64_t extractTokenIdFromKey(NodeKey* key) {
    uint64_t tokenId = 0;
    for (int i = 0; i < 8; i++) {
        tokenId <<= 8;
        uint8_t byte = (getNibble(key->nibble_path.nibbles, 8 + 2*i) << 4)
                     | getNibble(key->nibble_path.nibbles, 8 + 2*i + 1);
        tokenId |= byte;
    }
    return tokenId;
}

uint32_t extractVersionFromKey(NodeKey* key) {
    uint32_t version = 0;
    for (int i = 0; i < 4; i++) {
        version <<= 8;
        uint8_t byte = (getNibble(key->nibble_path.nibbles, 2*i) << 4)
                     | getNibble(key->nibble_path.nibbles, 2*i + 1);
        version |= byte;
    }
    return version;
}

void exportProofAndAncestry(const char* filename, Proof* proof, AncestryProof* ancestry, NodeKey* key, uint8_t* value, size_t valueLen, HashValue rootHash) {
    FILE* f = fopen(filename, "w");
    if (!f) {
        perror("Errore apertura file JSON");
        return;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"tokenId\": %lu,\n", extractTokenIdFromKey(key));
    fprintf(f, "  \"version\": %u,\n", extractVersionFromKey(key));
    fprintf(f, "  \"value\": \"%.*s\",\n", (int)valueLen, value);

    fprintf(f, "  \"root\": \"");
    for (int i = 0; i < 32; i++) fprintf(f, "%02x", rootHash.hash_bytes[i]);
    fprintf(f, "\",\n");

    // --- PROOF ---
    fprintf(f, "  \"proof\": {\n");
    fprintf(f, "    \"isMembership\": %s,\n", proof->isPresent ? "true" : "false");
    fprintf(f, "    \"depth\": %zu,\n", proof->depth);
    fprintf(f, "    \"tokenId\": %lu,\n", extractTokenIdFromKey(key));

    fprintf(f, "    \"leafHash\": \"");
    for (int i = 0; i < 32; i++) fprintf(f, "%02x", proof->leafHash.hash_bytes[i]);
    fprintf(f, "\",\n");

    fprintf(f, "    \"levels\": [\n");
    LevelSibling* lvl = proof->levels;
    size_t lvlIdx = 0;
    while (lvl != NULL) {
        fprintf(f, "      {\n        \"siblings\": [");
        Sibling* sib = lvl->siblings;
        int first = 1;
        while (sib != NULL) {
            if (!first) fprintf(f, ", ");
            fprintf(f, "{ \"index\": %u, \"hash\": \"", sib->index);
            for (int i = 0; i < 32; i++) fprintf(f, "%02x", sib->hash.hash_bytes[i]);
            fprintf(f, "\" }");
            first = 0;
            sib = sib->next;
        }
        fprintf(f, "]\n      }");
        lvl = lvl->next;
        lvlIdx++;
        if (lvl != NULL) fprintf(f, ",\n");
    }
    fprintf(f, "\n    ]\n  },\n");

    // --- ANCESTRY ---
    fprintf(f, "  \"ancestry\": {\n");
    fprintf(f, "    \"splitted\": %s,\n", ancestry->splitted ? "true" : "false");
    fprintf(f, "    \"preForkDepth\": %zu,\n", ancestry->preForkingDepth);

    // --- Aggiunta della chiave usata da ancestry ---
    fprintf(f, "    \"key\": {\n");
    fprintf(f, "      \"version\": %u,\n", extractVersionFromKey(&ancestry->key));
    fprintf(f, "      \"tokenId\": %lu\n", extractTokenIdFromKey(&ancestry->key));
    fprintf(f, "    },\n");

    fprintf(f, "    \"RootN\": \"");
    for (int i = 0; i < 32; i++) fprintf(f, "%02x", ancestry->RootN.hash_bytes[i]);
    fprintf(f, "\",\n");

    Proof* ap = &ancestry->proof;
    fprintf(f, "    \"P\": {\n");
    fprintf(f, "      \"isMembership\": %s,\n", ap->isPresent ? "true" : "false");
    fprintf(f, "      \"depth\": %zu,\n", ap->depth);
    fprintf(f, "      \"tokenId\": %lu,\n", extractTokenIdFromKey(&ancestry->key));

    fprintf(f, "      \"leafHash\": \"");
    for (int i = 0; i < 32; i++) fprintf(f, "%02x", ap->leafHash.hash_bytes[i]);
    fprintf(f, "\",\n");

    fprintf(f, "      \"levels\": [\n");
    lvl = ap->levels;
    lvlIdx = 0;
    while (lvl != NULL) {
        fprintf(f, "        {\n          \"siblings\": [");
        Sibling* sib = lvl->siblings;
        int first = 1;
        while (sib != NULL) {
            if (!first) fprintf(f, ", ");
            fprintf(f, "{ \"index\": %u, \"hash\": \"", sib->index);
            for (int i = 0; i < 32; i++) fprintf(f, "%02x", sib->hash.hash_bytes[i]);
            fprintf(f, "\" }");
            first = 0;
            sib = sib->next;
        }
        fprintf(f, "]\n        }");
        lvl = lvl->next;
        if (lvl != NULL) fprintf(f, ",\n");
    }
    fprintf(f, "\n      ]\n");
    fprintf(f, "    }\n");
    fprintf(f, "  }\n");

    fprintf(f, "}\n");
    fclose(f);
}

void processCSV(const char* csvPath) {
    FILE* file = fopen(csvPath, "r");
    if (!file) {
        perror("Errore apertura file CSV");
        exit(EXIT_FAILURE);
    }

    char line[256];
    int lineNum = 0;
    InternalNode* root = createInternalNode();

    fgets(line, sizeof(line), file);

    while (fgets(line, sizeof(line), file)) {
        uint32_t blockId, timestamp, contractId, fromId, toId;
        uint64_t tokenId;
        char value[] = "1";

        sscanf(line, "%u,%u,%u,%u,%u,%lu", &blockId, &timestamp, &contractId, &fromId, &toId, &tokenId);

        if (fromId!=0) {
            continue;
        }

        NibblePath path = buildPathFromTokenId(tokenId);
        NodeKey key = buildKey(path);

        insertJMT(&root, &key, (uint8_t*)value, strlen(value), &ancestryP);

        Proof proof = {0};
        generateProof(root, &key, &proof);

        AncestryProof ancestry = {0};
        ancestry.key = ancestryP.key;
        ancestry.RootN = ancestryP.RootN;
        ancestry.splitted = ancestryP.splitted;
        ancestry.preForkingDepth = ancestryP.preForkingDepth;
        ancestry.proof = deepCopyProof(&ancestryP.proof);

        char filename[128];
        sprintf(filename, "proofs/output_%05d.json", lineNum);
        HashValue rootHash = computeProofRoot(&key, &proof, proof.leafHash);

        exportProofAndAncestry(filename, &proof, &ancestry, &key, (uint8_t*)value, strlen(value), rootHash);

        free(path.nibbles);
        free(key.nibble_path.nibbles);

        lineNum++;

        if(lineNum%1000 == 0){
            printf("Numero di linea: %u\n",lineNum);
        }
    }
    fclose(file);
}

int main(int argc, char** argv) {
    const char* path = "art_blocks.csv";
    processCSV(path);
    return 0;
}
