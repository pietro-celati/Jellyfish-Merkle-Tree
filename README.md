# Jellyfish Merkle Tree — Materiali tesi

Questo repository contiene i materiali e il codice sviluppati per la tesi sui **Jellyfish Merkle Tree (JMT)** applicati alla certificazione di collezioni NFT.

---

## Struttura del repository

- **drawio/**  
  Contiene i diagrammi sorgente usati nella tesi in formato `.drawio`.  
  I file possono essere aperti con [https://app.diagrams.net/](https://app.diagrams.net/).

- **JMT/**  
  Implementazione off-chain in C dei Jellyfish Merkle Tree.  
  Permette di inserire, cercare ed eliminare chiavi, generare prove di inclusione, non-inclusione e ancestry, esportarle in JSON e verificarle off-chain.  
  La cartella include:
  - `include/` — header (`Jellyfish.h`, `keccak-tiny.h`, `macros.h`)
  - `src/` — sorgenti (`Jellyfish.c`, `keccak-tiny.c`, `exportProofs.c`, `verify_only.c`)
  - `Makefile` — script di compilazione
  - `bin/` — creato automaticamente dal Makefile e contenente gli eseguibili

- **Hardhat/**  
  Contiene il contratto Solidity `JmtERC721.sol` usato per la verifica delle prove on-chain.  

---

## Compilazione del codice C (JMT)

Assicurarsi di avere installato `gcc`. In alcuni casi potrebbe servire anche la libreria OpenSSL (`-lcrypto`).
