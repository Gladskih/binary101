"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  computePeAuthenticodeDigest,
  verifyAuthenticodeFileDigest
} from "../../analyzers/pe/authenticode-verify.js";
import type { AuthenticodeInfo } from "../../analyzers/pe/authenticode.js";
import {
  collectFixtureBytes,
  createBestEffortAuthenticodeFixture,
  createStrictAuthenticodeFixture,
  listStrictAuthenticodeHashRanges
} from "../fixtures/pe-authenticode-fixtures.js";

const toHex = (buffer: ArrayBuffer): string =>
  [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, "0")).join("");
const SUPPORTED_AUTHENTICODE_HASH_CASES = [
  { label: "sha1 lower", raw: "sha1", webCrypto: "SHA-1" },
  { label: "sha1 dashed", raw: "SHA-1", webCrypto: "SHA-1" },
  { label: "sha1 mixed", raw: "Sha_1", webCrypto: "SHA-1" },
  { label: "sha224 lower", raw: "sha224", webCrypto: "SHA-224" },
  { label: "sha224 dashed", raw: "SHA-224", webCrypto: "SHA-224" },
  { label: "sha224 mixed", raw: "Sha_224", webCrypto: "SHA-224" },
  { label: "sha256 lower", raw: "sha256", webCrypto: "SHA-256" },
  { label: "sha256 dashed", raw: "SHA-256", webCrypto: "SHA-256" },
  { label: "sha256 mixed", raw: "Sha_256", webCrypto: "SHA-256" },
  { label: "sha384 lower", raw: "sha384", webCrypto: "SHA-384" },
  { label: "sha384 dashed", raw: "SHA-384", webCrypto: "SHA-384" },
  { label: "sha384 mixed", raw: "Sha_384", webCrypto: "SHA-384" },
  { label: "sha512 lower", raw: "sha512", webCrypto: "SHA-512" },
  { label: "sha512 dashed", raw: "SHA-512", webCrypto: "SHA-512" },
  { label: "sha512 mixed", raw: "Sha_512", webCrypto: "SHA-512" }
] as const;

void test("verifyAuthenticodeFileDigest reports matching digests", async () => {
  const { core, file, securityDir } = createStrictAuthenticodeFixture();
  const computed = await computePeAuthenticodeDigest(file, core, securityDir, "SHA-256");
  assert.ok(computed);

  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    fileDigestAlgorithmName: "sha256",
    fileDigest: computed
  };
  const verified = await verifyAuthenticodeFileDigest(file, core, securityDir, auth);
  assert.strictEqual(verified.fileDigestMatches, true);
  assert.strictEqual(verified.computedFileDigest, computed);
});

void test("verifyAuthenticodeFileDigest accepts fileDigestAlgorithm field", async () => {
  const { core, file, securityDir } = createStrictAuthenticodeFixture();
  const computed = await computePeAuthenticodeDigest(file, core, securityDir, "SHA-256");
  assert.ok(computed);

  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    fileDigestAlgorithm: "sha256",
    fileDigest: computed
  };
  const verified = await verifyAuthenticodeFileDigest(file, core, securityDir, auth);
  assert.strictEqual(verified.fileDigestMatches, true);
});

void test("verifyAuthenticodeFileDigest accepts digestAlgorithms list", async () => {
  const { core, file, securityDir } = createStrictAuthenticodeFixture();
  const computed = await computePeAuthenticodeDigest(file, core, securityDir, "SHA-256");
  assert.ok(computed);

  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    digestAlgorithms: ["sha256"],
    fileDigest: computed
  };
  const verified = await verifyAuthenticodeFileDigest(file, core, securityDir, auth);
  assert.strictEqual(verified.fileDigestMatches, true);
});

void test("verifyAuthenticodeFileDigest supports canonical and punctuated names for all Web Crypto digest algorithms", async () => {
  const { bytes, core, file, securityDir } = createStrictAuthenticodeFixture();
  const expectedHashedBytes = collectFixtureBytes(bytes, listStrictAuthenticodeHashRanges());
  const expectedDigestBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  const expectedDigestHex = toHex(expectedDigestBytes.buffer);

  for (const hashCase of SUPPORTED_AUTHENTICODE_HASH_CASES) {
    const auth: AuthenticodeInfo = {
      format: "pkcs7",
      fileDigestAlgorithmName: hashCase.raw,
      fileDigest: expectedDigestHex
    };
    let seenAlgorithm: AlgorithmIdentifier | undefined;
    let seenData: Uint8Array | undefined;

    const verified = await verifyAuthenticodeFileDigest(
      file,
      core,
      securityDir,
      auth,
      async (algorithm: AlgorithmIdentifier, data: ArrayBuffer): Promise<ArrayBuffer> => {
        seenAlgorithm = algorithm;
        seenData = new Uint8Array(data);
        return expectedDigestBytes.slice().buffer;
      }
    );

    assert.strictEqual(verified.fileDigestMatches, true, hashCase.label);
    assert.strictEqual(verified.computedFileDigest, expectedDigestHex, hashCase.label);
    assert.strictEqual(seenAlgorithm, hashCase.webCrypto, hashCase.label);
    assert.deepStrictEqual(seenData, new Uint8Array(expectedHashedBytes), hashCase.label);
  }
});

void test("verifyAuthenticodeFileDigest warns on unsupported algorithms", async () => {
  const file = createBestEffortAuthenticodeFixture().file;
  const securityDir = { name: "SECURITY", index: 4, rva: 0, size: 0 };
  const core = { optOff: 0, ddStartRel: 0, dataDirs: [securityDir] };
  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    fileDigestAlgorithmName: "md5",
    fileDigest: "00"
  };
  const verified = await verifyAuthenticodeFileDigest(file, core, securityDir, auth);
  assert.ok(verified.warnings?.some(w => w.includes("Unsupported")));
});

void test("verifyAuthenticodeFileDigest reports mismatching digests without warnings", async () => {
  const { core, file, securityDir } = createStrictAuthenticodeFixture();
  const computed = await computePeAuthenticodeDigest(file, core, securityDir, "SHA-256");
  assert.ok(computed);

  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    fileDigestAlgorithmName: "sha256",
    fileDigest: computed === "00" ? "11" : "00"
  };
  const verified = await verifyAuthenticodeFileDigest(file, core, securityDir, auth);
  assert.strictEqual(verified.fileDigestMatches, false);
  assert.strictEqual(verified.computedFileDigest, computed);
  assert.strictEqual(verified.warnings, undefined);
});

void test("verifyAuthenticodeFileDigest warns when algorithm is missing", async () => {
  const file = createBestEffortAuthenticodeFixture().file;
  const securityDir = { name: "SECURITY", index: 4, rva: 0, size: 0 };
  const core = { optOff: 0, ddStartRel: 0, dataDirs: [securityDir] };
  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    fileDigest: "00"
  };
  const verified = await verifyAuthenticodeFileDigest(file, core, securityDir, auth);
  assert.ok(verified.warnings?.some(w => w.includes("Unsupported")));
});

void test("verifyAuthenticodeFileDigest warns when digest cannot be computed", async () => {
  const file = createBestEffortAuthenticodeFixture().file;
  const securityDir = { name: "SECURITY", index: 4, rva: 0, size: 0 };
  const core = { optOff: file.size, ddStartRel: 0, dataDirs: [securityDir] };
  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    fileDigestAlgorithmName: "sha256",
    fileDigest: "00"
  };
  const verified = await verifyAuthenticodeFileDigest(file, core, securityDir, auth);
  assert.ok(verified.warnings?.some(w => w.includes("Unable to compute")));
});

void test("verifyAuthenticodeFileDigest catches digest errors", async () => {
  const { core, file, securityDir } = createStrictAuthenticodeFixture();
  const computed = await computePeAuthenticodeDigest(file, core, securityDir, "SHA-256");
  assert.ok(computed);

  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    fileDigestAlgorithmName: "sha256",
    fileDigest: computed
  };

  const failingDigest = async (_algorithm: unknown, _data: ArrayBuffer): Promise<ArrayBuffer> => {
    throw new Error("boom");
  };

  const verified = await verifyAuthenticodeFileDigest(file, core, securityDir, auth, failingDigest);
  assert.ok(verified.warnings?.some(w => w.includes("Digest verification failed")));
});

void test("verifyAuthenticodeFileDigest warns when strict digest computation cannot read the checksum field", async () => {
  const file = createBestEffortAuthenticodeFixture().file;
  const core = {
    optOff: file.size,
    ddStartRel: 100,
    dataDirs: [],
    opt: { SizeOfHeaders: 0 },
    sections: []
  };
  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    fileDigestAlgorithmName: "sha256",
    fileDigest: "00"
  };

  const verified = await verifyAuthenticodeFileDigest(file, core, undefined, auth);
  assert.ok(verified.warnings?.some(w => w.includes("Unable to compute")));
});
