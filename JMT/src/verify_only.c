#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "Jellyfish.h"

#define MAX_PROOFS 100000
#define MAX_LINE_LENGTH 256
#define MAX_TOKEN_ID 10000000   // aggiungilo se non c'è


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

void exportProofOnly(const char* filename, Proof* proof, NodeKey* key, uint8_t* value, size_t valueLen, HashValue rootHash) {
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

    fprintf(f, "  \"proof\": {\n");
    fprintf(f, "    \"isMembership\": %s,\n", proof->isPresent ? "true" : "false");
    fprintf(f, "    \"depth\": %zu,\n", proof->depth);
    fprintf(f, "    \"tokenId\": %lu,\n", extractTokenIdFromKey(key));

    fprintf(f, "    \"leafHash\": \"");
    for (int i = 0; i < 32; i++) fprintf(f, "%02x", proof->leafHash.hash_bytes[i]);
    fprintf(f, "\",\n");

    fprintf(f, "    \"levels\": [\n");
    LevelSibling* lvl = proof->levels;
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
        if (lvl != NULL) fprintf(f, ",\n");
    }
    fprintf(f, "\n    ]\n  }\n");
    fprintf(f, "}\n");

    fclose(f);
}

void processCSV_TransfersOnly(const char* csvPath) {
    FILE* file = fopen(csvPath, "r");
    if (!file) {
        perror("Errore apertura file CSV");
        exit(EXIT_FAILURE);
    }

    printf("📦 Apertura file riuscita, costruisco il root node...\n");
    InternalNode* root = createInternalNode();
    if (!root) {
        fprintf(stderr, "❌ Errore: root è NULL\n");
        exit(EXIT_FAILURE);
    }
    printf("🌱 Root node creato correttamente\n");

    mkdir("proofs-verify", 0777);

    char line[MAX_LINE_LENGTH];
    int proofIndex = 0;
    int lineNum = 0;
    AncestryProof ancestry = {0};

    fgets(line, sizeof(line), file); // salta header

    while (fgets(line, sizeof(line), file)) {
        lineNum++;

        uint32_t blockId, timestamp, contractId, fromId, toId;
        uint64_t tokenId;
        char value[] = "1";

        int parsed = sscanf(line, "%u,%u,%u,%u,%u,%lu", &blockId, &timestamp, &contractId, &fromId, &toId, &tokenId);
        if (parsed != 6) {
            fprintf(stderr, "❌ Riga %d malformata (%d campi): %s", lineNum, parsed, line);
            continue;
        }

        NodeKey key = buildKeyWithControl(tokenId, fromId == 0);


        if (fromId == 0) {
            insertJMT(&root, &key, (uint8_t*)value, strlen(value), &ancestry);
        } else {
            Proof proof = {0};
            generateProof(root, &key, &proof);
            HashValue rootHash = computeProofRoot(&key, &proof, proof.leafHash);

            char filename[128];
            sprintf(filename, "proofs-verify/output_%05d.json", proofIndex);
            exportProofOnly(filename, &proof, &key, (uint8_t*)value, strlen(value), rootHash);

            proofIndex++;
            if (proofIndex % 1000 == 0) {
                printf("✅ %d trasferimenti elaborati\n", proofIndex);
            }
            if (proofIndex >= MAX_PROOFS-1) break;
        }

        if(lineNum%1000 == 0){
            printf("LineNum:%d\n",lineNum);
        }


        free(key.nibble_path.nibbles);
    }

    fclose(file);
}

int main(int argc, char** argv) {
    const char* filename = "art_blocks.csv";
    if (argc > 1) filename = argv[1];
    printf("📂 Leggo il file: %s\n", filename);
    processCSV_TransfersOnly(filename);
    return 0;
}
