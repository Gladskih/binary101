"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  computePeAuthenticodeDigest,
  computePeAuthenticodeDigestBestEffort,
  computePeAuthenticodeDigestFromParsedPe
} from "../../analyzers/pe/authenticode-verify.js";
import {
  collectFixtureBytes,
  createBestEffortAuthenticodeFixture,
  createStrictAuthenticodeFixture,
  listBestEffortAuthenticodeHashRanges,
  listLegacyBestEffortAuthenticodeHashRanges,
  listStrictAuthenticodeHashRanges
} from "../fixtures/pe-authenticode-fixtures.js";

const toHex = (buffer: ArrayBuffer): string =>
  [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, "0")).join("");

void test("computePeAuthenticodeDigest hashes PE with checksum and security excluded", async () => {
  const { bytes, core, file, securityDir } = createBestEffortAuthenticodeFixture();
  const expectedBytes = collectFixtureBytes(bytes, listBestEffortAuthenticodeHashRanges(bytes.length));
  const expectedDigest = toHex(await crypto.subtle.digest("SHA-256", expectedBytes));

  const computed = await computePeAuthenticodeDigestBestEffort(file, core, securityDir, "SHA-256");
  assert.strictEqual(computed, expectedDigest);
});

void test("computePeAuthenticodeDigest excludes overlay bytes beyond the last section", async () => {
  const { bytes, core, file, securityDir } = createStrictAuthenticodeFixture();
  const expectedBytes = collectFixtureBytes(bytes, listStrictAuthenticodeHashRanges());
  const expectedDigest = toHex(await crypto.subtle.digest("SHA-256", expectedBytes));

  const computed = await computePeAuthenticodeDigestFromParsedPe(file, core, securityDir, "SHA-256");
  assert.strictEqual(computed, expectedDigest);
});

void test("computePeAuthenticodeDigestFromParsedPe falls back to hashing through EOF when SizeOfHeaders is invalid and no sections exist", async () => {
  const { bytes, file } = createBestEffortAuthenticodeFixture();
  const core = {
    optOff: 0,
    ddStartRel: 100,
    dataDirs: [],
    opt: { SizeOfHeaders: 0 },
    sections: []
  };
  // With no sections and an invalid SizeOfHeaders, the strict helper can only hash the available bytes after the
  // checksum/security fields. Because no explicit SECURITY directory was supplied, this matches the legacy tail path.
  const expectedBytes = collectFixtureBytes(bytes, listLegacyBestEffortAuthenticodeHashRanges(bytes.length));
  const expectedDigest = toHex(await crypto.subtle.digest("SHA-256", expectedBytes));

  const computed = await computePeAuthenticodeDigestFromParsedPe(file, core, undefined, "SHA-256");
  assert.strictEqual(computed, expectedDigest);
});

void test("computePeAuthenticodeDigestFromParsedPe tolerates empty header hash ranges created by clamping", async () => {
  const { bytes, file } = createBestEffortAuthenticodeFixture();
  const securityDir = { name: "SECURITY", index: 4, rva: 120, size: 40 };
  const core = {
    optOff: 0,
    ddStartRel: 100,
    dataDirs: [securityDir],
    opt: { SizeOfHeaders: 1 },
    sections: []
  };
  // SizeOfHeaders=1 collapses the strict header range to the first byte, so the post-directory header hash range
  // becomes empty after clamping and must not produce a bogus slice.
  const expectedBytes = collectFixtureBytes(bytes, [
    { start: 0, end: 64 },
    { start: 68, end: 132 }
  ]);
  const expectedDigest = toHex(await crypto.subtle.digest("SHA-256", expectedBytes));

  const computed = await computePeAuthenticodeDigestFromParsedPe(file, core, securityDir, "SHA-256");
  assert.strictEqual(computed, expectedDigest);
});

void test("computePeAuthenticodeDigestFromParsedPe clamps overlapping certificate prefixes inside the hashed header range", async () => {
  const { bytes, file } = createBestEffortAuthenticodeFixture();
  const securityDir = { name: "SECURITY", index: 4, rva: 120, size: 40 };
  const core = {
    optOff: 0,
    ddStartRel: 100,
    dataDirs: [securityDir],
    opt: { SizeOfHeaders: bytes.length },
    sections: []
  };
  // The certificate starts before the hashed header range [140, EOF), so the helper must clamp the excluded prefix
  // and resume hashing from the certificate end.
  const expectedBytes = collectFixtureBytes(bytes, [
    { start: 0, end: 64 },
    { start: 68, end: 132 },
    { start: 160, end: bytes.length }
  ]);
  const expectedDigest = toHex(await crypto.subtle.digest("SHA-256", expectedBytes));

  const computed = await computePeAuthenticodeDigestFromParsedPe(file, core, securityDir, "SHA-256");
  assert.strictEqual(computed, expectedDigest);
});

void test("computePeAuthenticodeDigest uses SECURITY index from data directories when missing", async () => {
  const { bytes, core, file } = createBestEffortAuthenticodeFixture();
  const expectedBytes = collectFixtureBytes(bytes, listLegacyBestEffortAuthenticodeHashRanges(bytes.length));
  const expectedDigest = toHex(await crypto.subtle.digest("SHA-256", expectedBytes));

  const computed = await computePeAuthenticodeDigest(file, core, undefined, "SHA-256");
  assert.strictEqual(computed, expectedDigest);
});

void test("computePeAuthenticodeDigest falls back to default SECURITY index", async () => {
  const { bytes, file } = createBestEffortAuthenticodeFixture();
  const core = { optOff: 0, ddStartRel: 100, dataDirs: [] };
  const expectedBytes = collectFixtureBytes(bytes, listLegacyBestEffortAuthenticodeHashRanges(bytes.length));
  const expectedDigest = toHex(await crypto.subtle.digest("SHA-256", expectedBytes));

  const computed = await computePeAuthenticodeDigest(file, core, undefined, "SHA-256");
  assert.strictEqual(computed, expectedDigest);
});

void test("computePeAuthenticodeDigestBestEffort returns null when the checksum field is outside the file", async () => {
  const file = createBestEffortAuthenticodeFixture().file;
  const securityDir = { name: "SECURITY", index: 4, rva: 0, size: 0 };
  const core = { optOff: file.size, ddStartRel: 0, dataDirs: [securityDir] };

  const computed = await computePeAuthenticodeDigestBestEffort(file, core, securityDir, "SHA-256");
  assert.strictEqual(computed, null);
});

void test("computePeAuthenticodeDigestFromParsedPe returns null when the checksum field is outside the file", async () => {
  const file = createBestEffortAuthenticodeFixture().file;
  const core = {
    optOff: file.size,
    ddStartRel: 100,
    dataDirs: [],
    opt: { SizeOfHeaders: 0 },
    sections: []
  };

  const computed = await computePeAuthenticodeDigestFromParsedPe(file, core, undefined, "SHA-256");
  assert.strictEqual(computed, null);
});

void test("computePeAuthenticodeDigest dispatches to the strict parsed-PE path when section context is available", async () => {
  const { core, file, securityDir } = createStrictAuthenticodeFixture();
  const strictDigest = await computePeAuthenticodeDigestFromParsedPe(file, core, securityDir, "SHA-256");
  const dispatchedDigest = await computePeAuthenticodeDigest(file, core, securityDir, "SHA-256");

  assert.strictEqual(dispatchedDigest, strictDigest);
});

void test("computePeAuthenticodeDigestFromParsedPe orders sections by RVA before hashing", async () => {
  const { bytes, core, file } = createStrictAuthenticodeFixture();
  const originalSection = core.sections[0];
  assert.ok(originalSection);
  const splitRawSize = originalSection.sizeOfRawData / 2;
  const laterRvaRawOffset = originalSection.pointerToRawData;
  const earlierRvaRawOffset = laterRvaRawOffset + splitRawSize;
  const reorderedCore = {
    ...core,
    dataDirs: [],
    sections: [
      {
        ...originalSection,
        name: ".late",
        virtualSize: splitRawSize,
        virtualAddress: originalSection.virtualAddress + splitRawSize,
        sizeOfRawData: splitRawSize,
        pointerToRawData: laterRvaRawOffset
      },
      {
        ...originalSection,
        name: ".early",
        virtualSize: splitRawSize,
        sizeOfRawData: splitRawSize,
        pointerToRawData: earlierRvaRawOffset
      }
    ]
  };
  // Authenticode orders sections by address range before hashing, even if raw file offsets are out of order.
  const expectedBytes = collectFixtureBytes(bytes, [
    ...listLegacyBestEffortAuthenticodeHashRanges(reorderedCore.opt.SizeOfHeaders),
    { start: earlierRvaRawOffset, end: earlierRvaRawOffset + splitRawSize },
    { start: laterRvaRawOffset, end: laterRvaRawOffset + splitRawSize }
  ]);
  const expectedDigest = toHex(await crypto.subtle.digest("SHA-256", expectedBytes));

  const computed = await computePeAuthenticodeDigestFromParsedPe(
    file,
    reorderedCore,
    undefined,
    "SHA-256"
  );
  assert.strictEqual(computed, expectedDigest);
});

void test("computePeAuthenticodeDigest dispatches to the legacy best-effort path when parsed section context is absent", async () => {
  const { core, file, securityDir } = createBestEffortAuthenticodeFixture();
  const bestEffortDigest = await computePeAuthenticodeDigestBestEffort(file, core, securityDir, "SHA-256");
  const dispatchedDigest = await computePeAuthenticodeDigest(file, core, securityDir, "SHA-256");

  assert.strictEqual(dispatchedDigest, bestEffortDigest);
});
