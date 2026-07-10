"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseGoRuntimeMetadata } from "../../../../analyzers/go-runtime/parser.js";
import { createGoRuntimeFixture } from "../../../fixtures/go-runtime.js";

const parseFixture = (fixture: ReturnType<typeof createGoRuntimeFixture>) =>
  parseGoRuntimeMetadata(fixture.image, fixture.pcHeaderAddress, fixture.moduleDataAddress);

void test("parseGoRuntimeMetadata rejects module and slice pointer inconsistencies", async () => {
  const wrongHeader = createGoRuntimeFixture("go1.20+");
  new DataView(wrongHeader.moduleBytes.buffer).setBigUint64(0, wrongHeader.pcHeaderAddress + 8n, true);
  const wrongTable = createGoRuntimeFixture("go1.20+");
  new DataView(wrongTable.moduleBytes.buffer).setBigUint64(8, wrongTable.pcHeaderAddress + 80n, true);
  const wrongFunctab = createGoRuntimeFixture("go1.20+");
  new DataView(wrongFunctab.moduleBytes.buffer).setBigUint64(
    16 * 8,
    wrongFunctab.pcHeaderAddress + 8n,
    true
  );
  const wrongFunctionCount = createGoRuntimeFixture("go1.20+");
  new DataView(wrongFunctionCount.moduleBytes.buffer).setBigUint64(17 * 8, 2n, true);

  assert.equal(await parseFixture(wrongHeader), null);
  assert.equal(await parseFixture(wrongTable), null);
  assert.equal(await parseFixture(wrongFunctab), null);
  assert.equal(await parseFixture(wrongFunctionCount), null);
});

void test("parseGoRuntimeMetadata rejects file count and UTF-8 inconsistencies", async () => {
  const wrongCount = createGoRuntimeFixture("go1.20+");
  new DataView(wrongCount.headerBytes.buffer).setBigUint64(16, 1n, true);
  const invalidUtf8 = createGoRuntimeFixture("go1.20+");
  const fileAddress = new DataView(invalidUtf8.moduleBytes.buffer).getBigUint64(7 * 8, true);
  invalidUtf8.headerBytes[Number(fileAddress - invalidUtf8.pcHeaderAddress)] = 0xff;

  assert.equal(await parseFixture(wrongCount), null);
  assert.equal(await parseFixture(invalidUtf8), null);
});

void test("parseGoRuntimeMetadata accepts dead-file sentinels in cutab", async () => {
  const fixture = createGoRuntimeFixture("go1.20+");
  const cutabAddress = new DataView(fixture.moduleBytes.buffer).getBigUint64(4 * 8, true);
  new DataView(fixture.headerBytes.buffer).setUint32(
    Number(cutabAddress - fixture.pcHeaderAddress),
    0xffff_ffff,
    true
  );

  const result = await parseFixture(fixture);

  assert.ok(result);
});

void test("parseGoRuntimeMetadata rejects malformed functab rows", async () => {
  const badOffset = createGoRuntimeFixture("go1.20+");
  const badOffsetPcln = Number(
    new DataView(badOffset.moduleBytes.buffer).getBigUint64(13 * 8, true) - badOffset.pcHeaderAddress
  );
  new DataView(badOffset.headerBytes.buffer).setUint32(badOffsetPcln + 4, 0xffff_ffff, true);
  const badEntry = createGoRuntimeFixture("go1.20+");
  const badEntryPcln = Number(
    new DataView(badEntry.moduleBytes.buffer).getBigUint64(13 * 8, true) - badEntry.pcHeaderAddress
  );
  new DataView(badEntry.headerBytes.buffer).setUint32(badEntryPcln + 24, 1, true);
  const zeroRange = createGoRuntimeFixture("go1.20+");
  const zeroPcln = Number(
    new DataView(zeroRange.moduleBytes.buffer).getBigUint64(13 * 8, true) - zeroRange.pcHeaderAddress
  );
  new DataView(zeroRange.headerBytes.buffer).setUint32(zeroPcln + 8, 0, true);

  assert.equal(await parseFixture(badOffset), null);
  assert.equal(await parseFixture(badEntry), null);
  assert.equal(await parseFixture(zeroRange), null);
});

void test("parseGoRuntimeMetadata rejects inconsistent module text boundaries", async () => {
  const wrongMinimum = createGoRuntimeFixture("go1.20+");
  new DataView(wrongMinimum.moduleBytes.buffer).setBigUint64(
    20 * 8,
    wrongMinimum.textAddress + 1n,
    true
  );
  const emptyText = createGoRuntimeFixture("go1.20+");
  new DataView(emptyText.moduleBytes.buffer).setBigUint64(23 * 8, emptyText.textAddress, true);
  const wrongHeaderText = createGoRuntimeFixture("go1.20+");
  new DataView(wrongHeaderText.headerBytes.buffer).setBigUint64(
    8 + 2 * 8,
    wrongHeaderText.textAddress + 8n,
    true
  );
  const shortText = createGoRuntimeFixture("go1.20+");
  new DataView(shortText.moduleBytes.buffer).setBigUint64(
    23 * 8,
    shortText.textAddress + 0x30n,
    true
  );
  const missingLookup = createGoRuntimeFixture("go1.20+");
  new DataView(missingLookup.moduleBytes.buffer).setBigUint64(19 * 8, 0n, true);

  assert.equal(await parseFixture(wrongMinimum), null);
  assert.equal(await parseFixture(emptyText), null);
  assert.equal(await parseFixture(wrongHeaderText), null);
  assert.equal(await parseFixture(shortText), null);
  assert.equal(await parseFixture(missingLookup), null);
});

void test("parseGoRuntimeMetadata rejects invalid table gaps and name offsets", async () => {
  const badGap = createGoRuntimeFixture("go1.20+");
  const badGapView = new DataView(badGap.moduleBytes.buffer);
  badGapView.setBigUint64(2 * 8, 1n, true);
  badGapView.setBigUint64(3 * 8, 1n, true);
  const badName = createGoRuntimeFixture("go1.20+");
  const pclnAddress = new DataView(badName.moduleBytes.buffer).getBigUint64(13 * 8, true);
  const pclnOffset = Number(pclnAddress - badName.pcHeaderAddress);
  new DataView(badName.headerBytes.buffer).setInt32(pclnOffset + 28, -1, true);
  const badHeader = createGoRuntimeFixture("go1.20+");
  new DataView(badHeader.headerBytes.buffer).setUint32(0, 0, true);

  assert.equal(await parseFixture(badGap), null);
  assert.equal(await parseFixture(badName), null);
  assert.equal(await parseFixture(badHeader), null);
});
