"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { computePeAuthenticodeDigest, verifyAuthenticodeFileDigest } from "../../analyzers/pe/authenticode-verify.js";
import type { AuthenticodeInfo } from "../../analyzers/pe/authenticode.js";
import { MockFile } from "../helpers/mock-file.js";

const toHex = (buffer: ArrayBuffer): string =>
  [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, "0")).join("");

void test("computePeAuthenticodeDigest hashes PE with checksum and security excluded", async () => {
  const bytes = new Uint8Array(200);
  bytes.forEach((_, index) => {
    bytes[index] = index;
  });
  const file = new MockFile(bytes, "digest.exe");
  const securityDir = { name: "SECURITY", index: 4, rva: 160, size: 20 };
  const core = { optOff: 0, ddStartRel: 100, dataDirs: [securityDir] };

  const expectedBytes = new Uint8Array([
    ...bytes.slice(0, 64),
    ...bytes.slice(68, 132),
    ...bytes.slice(140, 160),
    ...bytes.slice(180)
  ]);
  const expectedDigest = toHex(await crypto.subtle.digest("SHA-256", expectedBytes));

  const computed = await computePeAuthenticodeDigest(file, core, securityDir, "SHA-256");
  assert.strictEqual(computed, expectedDigest);
});

void test("computePeAuthenticodeDigest uses SECURITY index from data directories when missing", async () => {
  const bytes = new Uint8Array(200);
  bytes.forEach((_, index) => {
    bytes[index] = index;
  });
  const file = new MockFile(bytes, "digest.exe");
  const securityDir = { name: "SECURITY", index: 4, rva: 160, size: 20 };
  const core = { optOff: 0, ddStartRel: 100, dataDirs: [securityDir] };

  const expectedBytes = new Uint8Array([
    ...bytes.slice(0, 64),
    ...bytes.slice(68, 132),
    ...bytes.slice(140)
  ]);
  const expectedDigest = toHex(await crypto.subtle.digest("SHA-256", expectedBytes));

  const computed = await computePeAuthenticodeDigest(file, core, undefined, "SHA-256");
  assert.strictEqual(computed, expectedDigest);
});

void test("computePeAuthenticodeDigest falls back to default SECURITY index", async () => {
  const bytes = new Uint8Array(200);
  bytes.forEach((_, index) => {
    bytes[index] = index;
  });
  const file = new MockFile(bytes, "digest.exe");
  const core = { optOff: 0, ddStartRel: 100, dataDirs: [] };

  const expectedBytes = new Uint8Array([
    ...bytes.slice(0, 64),
    ...bytes.slice(68, 132),
    ...bytes.slice(140)
  ]);
  const expectedDigest = toHex(await crypto.subtle.digest("SHA-256", expectedBytes));

  const computed = await computePeAuthenticodeDigest(file, core, undefined, "SHA-256");
  assert.strictEqual(computed, expectedDigest);
});

void test("verifyAuthenticodeFileDigest reports matching digests", async () => {
  const bytes = new Uint8Array(200);
  bytes.forEach((_, index) => {
    bytes[index] = index;
  });
  const file = new MockFile(bytes, "digest.exe");
  const securityDir = { name: "SECURITY", index: 4, rva: 160, size: 20 };
  const core = { optOff: 0, ddStartRel: 100, dataDirs: [securityDir] };
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
  const bytes = new Uint8Array(200);
  bytes.forEach((_, index) => {
    bytes[index] = index;
  });
  const file = new MockFile(bytes, "digest.exe");
  const securityDir = { name: "SECURITY", index: 4, rva: 160, size: 20 };
  const core = { optOff: 0, ddStartRel: 100, dataDirs: [securityDir] };
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
  const bytes = new Uint8Array(200);
  bytes.forEach((_, index) => {
    bytes[index] = index;
  });
  const file = new MockFile(bytes, "digest.exe");
  const securityDir = { name: "SECURITY", index: 4, rva: 160, size: 20 };
  const core = { optOff: 0, ddStartRel: 100, dataDirs: [securityDir] };
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

void test("verifyAuthenticodeFileDigest warns on unsupported algorithms", async () => {
  const bytes = new Uint8Array(64).fill(0);
  const file = new MockFile(bytes, "digest.exe");
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

void test("verifyAuthenticodeFileDigest warns when algorithm is missing", async () => {
  const bytes = new Uint8Array(64).fill(0);
  const file = new MockFile(bytes, "digest.exe");
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
  const bytes = new Uint8Array(10).fill(0);
  const file = new MockFile(bytes, "tiny.exe");
  const securityDir = { name: "SECURITY", index: 4, rva: 0, size: 0 };
  const core = { optOff: 0, ddStartRel: 0, dataDirs: [securityDir] };
  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    fileDigestAlgorithmName: "sha256",
    fileDigest: "00"
  };
  const verified = await verifyAuthenticodeFileDigest(file, core, securityDir, auth);
  assert.ok(verified.warnings?.some(w => w.includes("Unable to compute")));
});

void test("verifyAuthenticodeFileDigest catches digest errors", async () => {
  const bytes = new Uint8Array(200);
  bytes.forEach((_, index) => {
    bytes[index] = index;
  });
  const file = new MockFile(bytes, "digest.exe");
  const securityDir = { name: "SECURITY", index: 4, rva: 160, size: 20 };
  const core = { optOff: 0, ddStartRel: 100, dataDirs: [securityDir] };
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
