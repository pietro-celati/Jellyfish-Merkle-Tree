CC=gcc
CFLAGS=-O3 -Wall -Iinclude
LDFLAGS=
SRC_DIR=src
BIN_DIR=bin

COMMON=$(SRC_DIR)/Jellyfish.c $(SRC_DIR)/keccak-tiny.c
EXPORT=$(SRC_DIR)/exportProofs.c
VERIFY=$(SRC_DIR)/verify_only.c

all: dirs jmt_export jmt_verify_only

dirs:
	mkdir -p $(BIN_DIR)

jmt_export: $(COMMON) $(EXPORT)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/jmt_export $(COMMON) $(EXPORT) $(LDFLAGS)

jmt_verify_only: $(COMMON) $(VERIFY)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/jmt_verify_only $(COMMON) $(VERIFY) $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR)
