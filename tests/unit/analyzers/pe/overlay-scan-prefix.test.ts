"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeOverlay } from "../../../../analyzers/pe/overlay.js";
import {
  findEmbeddedPayloadsInRangePrefix,
  scanPeOverlayRange
} from "../../../../analyzers/pe/overlay-scan.js";
import { createOverlayInputsWithPayload } from "../../../fixtures/pe-overlay-fixtures.js";
import { createSevenZipFile } from "../../../fixtures/rar-sevenzip-fixtures.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const getRange = async (payload: Uint8Array) => {
  const fixture = createOverlayInputsWithPayload(payload);
  const analysis = expectDefined(await analyzePeOverlay(fixture.inputs));
  return { fixture, range: expectDefined(analysis.ranges[0]) };
};

const withPrefixAndTail = (
  prefix: Uint8Array,
  archive: Uint8Array,
  tail = Uint8Array.of()
): Uint8Array => {
  const bytes = new Uint8Array(prefix.byteLength + archive.byteLength + tail.byteLength);
  bytes.set(prefix);
  bytes.set(archive, prefix.byteLength);
  bytes.set(tail, prefix.byteLength + archive.byteLength);
  return bytes;
};

void test("scanPeOverlayRange rejects a 7z next-header CRC mismatch", async () => {
  const sevenZip = createSevenZipFile().data.slice();
  sevenZip[sevenZip.byteLength - 1] = (sevenZip[sevenZip.byteLength - 1] ?? 0) ^ 0xff;
  const { fixture, range } = await getRange(sevenZip);

  const scanned = await scanPeOverlayRange(fixture.inputs.file, fixture.inputs.reader, range);

  assert.deepEqual(scanned.findings, []);
});

void test("findEmbeddedPayloadsInRangePrefix keeps full 7z bounds from a limited search", async () => {
  const prefix = new Uint8Array(64);
  const sevenZip = createSevenZipFile().data;
  const { fixture, range } = await getRange(withPrefixAndTail(prefix, sevenZip, Uint8Array.of(1)));

  const findings = await findEmbeddedPayloadsInRangePrefix(
    fixture.inputs.file,
    fixture.inputs.reader,
    range,
    prefix.byteLength + 1
  );

  assert.equal(findings[0]?.start, fixture.overlayStart + prefix.byteLength);
  assert.equal(findings[0]?.end, fixture.overlayStart + prefix.byteLength + sevenZip.byteLength);
});

void test("findEmbeddedPayloadsInRangePrefix does not inspect bytes beyond its limit", async () => {
  const prefix = new Uint8Array(64);
  const sevenZip = createSevenZipFile().data;
  const { fixture, range } = await getRange(withPrefixAndTail(prefix, sevenZip));

  const findings = await findEmbeddedPayloadsInRangePrefix(
    fixture.inputs.file,
    fixture.inputs.reader,
    range,
    prefix.byteLength
  );

  assert.deepEqual(findings, []);
});

void test("findEmbeddedPayloadsInRangePrefix rejects invalid limits", async () => {
  const { fixture, range } = await getRange(new Uint8Array(64));

  const findings = await findEmbeddedPayloadsInRangePrefix(
    fixture.inputs.file,
    fixture.inputs.reader,
    range,
    Number.NaN
  );

  assert.deepEqual(findings, []);
});
