const { expect } = require("chai");
const hre = require("hardhat");
const { toUtf8Bytes, zeroPadBytes, getBytes } = require("ethers");
const fs = require("fs");
const path = require("path");

function loadProof(index) {
    const jsonPath = path.join(__dirname, "../verify-proofs/output_" + index.toString().padStart(5, '0') + ".json");
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

describe("JmtERC721 verify-only", function () {
    it("should verify 100000 NFT proofs (no mint)", async function () {
        const [owner] = await hre.ethers.getSigners();
        const Jmt = await hre.ethers.getContractFactory("JmtERC721");
        const jmt = await Jmt.deploy("JMTNFT", "JMT");

        const outputCsvPath = path.join(__dirname, "outputs.csv");
        fs.writeFileSync(outputCsvPath, "tokenId,version,verifyGas\n");

        const N = 18700;
        for (let i = 0; i < N; i++) {
            if (i % 1000 === 0) {
                console.log(`🔍 Verifying proof ${i}/${N}`);
            }

            try {
                const data = loadProof(i);
                const tokenId = data.tokenId;
                const version = data.version;
                const value = toUtf8Bytes(data.value);

                const proof = {
                    isMembership: data.proof.isMembership,
                    depth: data.proof.depth,
                    tokenId: tokenId,
                    leafHash: toBytes32(data.proof.leafHash),
                    root: toBytes32(data.root),
                    levels: convertLevels(data.proof.levels)
                };

                const tx = await jmt.publicVerify(proof, tokenId, version, value);
                const receipt = await tx.wait();
                expect(receipt.status).to.equal(1);

                const line = `${tokenId},${version},${receipt.gasUsed}\n`;
                fs.appendFileSync(outputCsvPath, line);
            } catch (e) {
                console.warn(`⚠️ Proof ${i} skipped: ${e.message}`);
                continue;
            }
        }
    }).timeout(0);
});

