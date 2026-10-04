"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  computePeAuthenticodeDigest,
  computePeAuthenticodeDigestFromParsedPe,
  verifyAuthenticodeFileDigest
} from "../../../../../analyzers/pe/authenticode/digest.js";
import type { AuthenticodeInfo } from "../../../../../analyzers/pe/authenticode/index.js";
import { createParsedGappedAuthenticodeFixture } from "../../../../fixtures/pe-authenticode-gapped-file.js";
import { MockFile } from "../../../../helpers/mock-file.js";

// Independent SHA-256 oracles from Windows 11 build 26200, CryptSIPCreateIndirectData:
// https://learn.microsoft.com/en-us/windows/win32/api/mssip/nf-mssip-cryptsipcreateindirectdata
// Gaps are one PE FileAlignment unit (512 bytes), filled with nonzero patterned bytes.
void test("computePeAuthenticodeDigest hashes the gap before the first section like Windows", async () => {
  const { file, core, securityDir } = await createParsedGappedAuthenticodeFixture(512, 0);

  const computed = await computePeAuthenticodeDigestFromParsedPe(
    file, core, securityDir, "SHA-256"
  );

  assert.equal(computed, "936d378fc8e233d15fb4d80b244afa45142417b0b7aca40bc72fbb150ef2b204");
});

void test("computePeAuthenticodeDigest hashes the gap between sections like Windows", async () => {
  const { file, core, securityDir } = await createParsedGappedAuthenticodeFixture(0, 512);

  const computed = await computePeAuthenticodeDigestFromParsedPe(
    file, core, securityDir, "SHA-256"
  );

  assert.equal(computed, "beb5f3a9c6b9f97fccc9363dd1c5ece87bc9688a912b75b979ab418078ef079e");
});

void test("computePeAuthenticodeDigest dispatch preserves both gaps in the Windows image hash", async () => {
  const { file, core, securityDir } = await createParsedGappedAuthenticodeFixture(512, 512);

  const computed = await computePeAuthenticodeDigest(
    file, core, securityDir, "SHA-256"
  );

  assert.equal(computed, "55297e0f06025ae3fc63b558997836830d6b2e2e806823b329a2235687afdc5f");
});

void test("computePeAuthenticodeDigest detects a changed byte outside all section ranges", async () => {
  const { file, core, securityDir } = await createParsedGappedAuthenticodeFixture(512, 512);
  const modified = file.data.slice();
  modified[core.opt.SizeOfHeaders] = (modified[core.opt.SizeOfHeaders] ?? 0) ^ 0xff;

  const originalDigest = await computePeAuthenticodeDigest(file, core, securityDir, "SHA-256");
  const modifiedDigest = await computePeAuthenticodeDigest(
    new MockFile(modified), core, securityDir, "SHA-256"
  );

  assert.notEqual(originalDigest, modifiedDigest);
});

void test("verifyAuthenticodeFileDigest accepts the Windows digest of an image with gaps", async () => {
  const { file, core, securityDir } = await createParsedGappedAuthenticodeFixture(512, 512);
  // CryptSIPCreateIndirectData SHA-256, Windows 11 build 26200; independent of the analyzer.
  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    fileDigestAlgorithmName: "sha256",
    fileDigest: "55297e0f06025ae3fc63b558997836830d6b2e2e806823b329a2235687afdc5f"
  };

  const verified = await verifyAuthenticodeFileDigest(
    file, core, securityDir, auth
  );

  assert.equal(verified.fileDigestMatches, true);
  assert.equal(verified.computedFileDigest, auth.fileDigest);
  assert.equal(verified.warnings, undefined);
});

void test("verifyAuthenticodeFileDigest rejects a digest that omits image gaps", async () => {
  const { file, core, securityDir } = await createParsedGappedAuthenticodeFixture(512, 512);
  // Recorded pre-fix digest: headers + sections, omitting both 512-byte gaps.
  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    fileDigestAlgorithmName: "sha256",
    fileDigest: "77a486f0437e99be01bf23d4340f88f70d541b8449b20611fcc69824407c7565"
  };

  const verified = await verifyAuthenticodeFileDigest(
    file, core, securityDir, auth
  );

  assert.equal(verified.fileDigestMatches, false);
  assert.equal(verified.warnings, undefined);
});

void test("computePeAuthenticodeDigest rejects a checksum starting exactly at EOF", async () => {
  const { file, core, securityDir } = await createParsedGappedAuthenticodeFixture(512, 512);
  // PE Optional Header CheckSum offset is +64; no checksum bytes remain at this boundary.
  const boundaryCore = { ...core, optOff: file.size - 64 };

  const computed = await computePeAuthenticodeDigest(file, boundaryCore, securityDir, "SHA-256");

  assert.equal(computed, null);
});

void test("verifyAuthenticodeFileDigest reports a missing digest without computing one", async () => {
  const { file, core, securityDir } = await createParsedGappedAuthenticodeFixture(512, 512);

  const verified = await verifyAuthenticodeFileDigest(file, core, securityDir, { format: "pkcs7" });

  assert.deepEqual(verified, {
    warnings: ["Signature payload does not include a file digest."]
  });
});
