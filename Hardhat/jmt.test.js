const { expect } = require("chai");
const hre = require("hardhat");
const { toUtf8Bytes, zeroPadBytes, getBytes } = require("ethers");
const fs = require("fs");
const path = require("path");

function loadProof(index) {
    const jsonPath = path.join(__dirname, "../proofs/output_" + index.toString().padStart(5, '0') + ".json");
    return JSON.parse(fs.readFileSync(jsonPath));
}

function toBytes32(hexString) {
    return zeroPadBytes(getBytes("0x" + hexString), 32);
}

function convertLevels(levelsRaw) {
    return levelsRaw.map(level => ({
        siblings: level.siblings.map(s => ({
            index: s.index,
            hash: toBytes32(s.hash)
        }))
    }));
}

describe("JmtERC721 contract", function () {
    it("should mint and verify 72000 NFTs using C-generated proofs", async function () {
        const [owner] = await hre.ethers.getSigners();
        const Jmt = await hre.ethers.getContractFactory("JmtERC721");
        const jmt = await Jmt.deploy("JMTNFT", "JMT");

        const outputCsvPath = path.join(__dirname, "gas_results3.csv");
        fs.writeFileSync(outputCsvPath, "tokenId,version,mintGas,verifyGas\n"); // intestazione

        const N = 63000;
        for (let i = 0; i < N; i++) {
            if (i % 1000 === 0) {
                console.log(`🔄 Processing proof ${i}/${N}`);
            }

            const data = loadProof(i);
            const tokenId = data.tokenId;
            const version = data.version;
            const value = toUtf8Bytes(data.value);

            const proof = {
                isMembership: true,
                depth: data.proof.depth,
                tokenId,
                leafHash: toBytes32(data.proof.leafHash),
                root: toBytes32(data.root),
                levels: convertLevels(data.proof.levels)
            };

            const P = data.ancestry.P;
            const ancestry = {
                splitted: data.ancestry.splitted,
                preForkDepth: data.ancestry.preForkDepth,
                tokenId: data.ancestry.key.tokenId,
                version: data.ancestry.key.version,
                P: {
                    isMembership: P.isMembership,
                    depth: P.depth,
                    tokenId: P.tokenId,
                    leafHash: toBytes32(P.leafHash),
                    root: toBytes32(data.root),
                    levels: convertLevels(P.levels)
                }
            };

            const mintTx = await jmt.mint(tokenId, version, value, proof, ancestry);
            const mintReceipt = await mintTx.wait();
            expect(await jmt.ownerOf(tokenId)).to.equal(owner.address);

            const verifyTx = await jmt.publicVerify(proof, tokenId, version, value);
            const verifyReceipt = await verifyTx.wait();
            expect(verifyReceipt.status).to.equal(1);

            // ⬇️ Scrittura nel CSV
            const line = `${tokenId},${version},${mintReceipt.gasUsed},${verifyReceipt.gasUsed}\n`;
            fs.appendFileSync(outputCsvPath, line);
        }
    }).timeout(0); // ⏱️ Disattiva timeout di Mocha per test lunghi

});

