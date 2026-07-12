"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeOverlay } from "../../../../analyzers/pe/overlay.js";
import { scanPeOverlayRange } from "../../../../analyzers/pe/overlay-scan.js";
import { createOverlayInputsWithPayload } from "../../../fixtures/pe-overlay-fixtures.js";
import { createRar4File, createRar5File } from "../../../fixtures/rar-sevenzip-fixtures.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const createNonCandidatePaddingBytes = (): Uint8Array =>
  new Uint8Array(Uint8Array.BYTES_PER_ELEMENT);

const createEmbeddedPayload = (archiveBytes: Uint8Array): Uint8Array => {
  const paddingBytes = createNonCandidatePaddingBytes();
  const payloadBytes = new Uint8Array(
    paddingBytes.byteLength * 2 + archiveBytes.byteLength
  );
  payloadBytes.set(paddingBytes);
  payloadBytes.set(archiveBytes, paddingBytes.byteLength);
  payloadBytes.set(paddingBytes, paddingBytes.byteLength + archiveBytes.byteLength);
  return payloadBytes;
};

const scanOverlayPayload = async (payloadBytes: Uint8Array) => {
  const fixture = createOverlayInputsWithPayload(payloadBytes);
  const analysis = expectDefined(await analyzePeOverlay(fixture.inputs));
  const range = await scanPeOverlayRange(
    fixture.inputs.file,
    fixture.inputs.reader,
    expectDefined(analysis.ranges[0])
  );
  return { fixture, range };
};

void test("scanPeOverlayRange recognizes an embedded RAR4 archive", async () => {
  const archive = createRar4File().data;
  const { fixture, range } = await scanOverlayPayload(createEmbeddedPayload(archive));
  const finding = expectDefined(range.findings[0]);

  assert.equal(finding.start, fixture.overlayStart + createNonCandidatePaddingBytes().byteLength);
  assert.equal(finding.end, finding.start + archive.byteLength);
  assert.equal(finding.detectedType, "RAR archive");
});

void test("scanPeOverlayRange recognizes an embedded RAR5 archive", async () => {
  const archive = createRar5File().data;
  const { fixture, range } = await scanOverlayPayload(createEmbeddedPayload(archive));
  const finding = expectDefined(range.findings[0]);

  assert.equal(finding.start, fixture.overlayStart + createNonCandidatePaddingBytes().byteLength);
  assert.equal(finding.end, finding.start + archive.byteLength);
  assert.equal(finding.detectedType, "RAR archive");
});

void test("scanPeOverlayRange rejects a truncated RAR signature", async () => {
  // RAR4's signature is seven bytes: Rar! followed by 1A 07 00.
  const truncatedSignature = Uint8Array.of(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07);
  const { range } = await scanOverlayPayload(truncatedSignature);

  assert.deepEqual(range.findings, []);
});

void test("scanPeOverlayRange rejects a RAR signature without a main header", async () => {
  // RAR4's complete signature alone is not enough to establish an archive payload.
  const signatureWithoutHeader = Uint8Array.of(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00);
  const { range } = await scanOverlayPayload(signatureWithoutHeader);

  assert.deepEqual(range.findings, []);
});

void test("scanPeOverlayRange rejects a RAR5 end-header CRC mismatch", async () => {
  const bytes = createRar5File().data.slice();
  // The synthetic RAR5 end header is eight bytes and starts with its four-byte CRC.
  bytes[bytes.byteLength - 8] = (bytes[bytes.byteLength - 8] ?? 0) ^ 0xff;

  const { range } = await scanOverlayPayload(bytes);

  assert.deepEqual(range.findings, []);
});
