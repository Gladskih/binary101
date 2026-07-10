"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseGoPcHeader,
  parseGoRuntimeMetadata
} from "../../../../analyzers/go-runtime/parser.js";
import type { GoRuntimeLayout } from "../../../../analyzers/go-runtime/types.js";
import { createGoRuntimeFixture } from "../../../fixtures/go-runtime.js";

const layouts: GoRuntimeLayout[] = ["go1.16-1.17", "go1.18-1.19", "go1.20+"];

for (const layout of layouts) {
  void test(`parseGoRuntimeMetadata strictly parses ${layout}`, async () => {
    const fixture = createGoRuntimeFixture(layout);

    const result = await parseGoRuntimeMetadata(
      fixture.image,
      fixture.pcHeaderAddress,
      fixture.moduleDataAddress
    );

    assert.ok(result);
    assert.equal(result.layout, layout);
    assert.equal(result.functions.length, 2);
    assert.equal(result.fileCount, 2);
    assert.deepEqual(result.textRange, {
      start: fixture.textAddress,
      end: fixture.textAddress + 0x40n
    });
    assert.deepEqual(result.functions, [
      { name: "runtime.main", start: fixture.textAddress, end: fixture.textAddress + 0x20n },
      { name: "main.main", start: fixture.textAddress + 0x20n, end: fixture.textAddress + 0x40n }
    ]);
  });
}

void test("parseGoPcHeader rejects an unsupported magic", async () => {
  const fixture = createGoRuntimeFixture("go1.20+");
  new DataView(fixture.headerBytes.buffer).setUint32(0, 0xffff_fffb, true);

  const result = await parseGoPcHeader(fixture.image, fixture.pcHeaderAddress);

  assert.equal(result, null);
});

void test("parseGoPcHeader rejects invalid padding and pointer sizes", async () => {
  const badPadding = createGoRuntimeFixture("go1.20+");
  badPadding.headerBytes[4] = 1;
  const badPointer = createGoRuntimeFixture("go1.20+");
  badPointer.headerBytes[7] = 16;

  assert.equal(await parseGoPcHeader(badPadding.image, badPadding.pcHeaderAddress), null);
  assert.equal(await parseGoPcHeader(badPointer.image, badPointer.pcHeaderAddress), null);
});

void test("parseGoRuntimeMetadata rejects a truncated moduledata", async () => {
  const fixture = createGoRuntimeFixture("go1.20+");
  fixture.regions[2]!.bytes = fixture.moduleBytes.slice(0, 32);

  const result = await parseGoRuntimeMetadata(
    fixture.image,
    fixture.pcHeaderAddress,
    fixture.moduleDataAddress
  );

  assert.equal(result, null);
});

void test("parseGoRuntimeMetadata rejects an inconsistent slice capacity", async () => {
  const fixture = createGoRuntimeFixture("go1.20+");
  const view = new DataView(fixture.moduleBytes.buffer);
  view.setBigUint64(3 * 8, 24n, true);

  const result = await parseGoRuntimeMetadata(
    fixture.image,
    fixture.pcHeaderAddress,
    fixture.moduleDataAddress
  );

  assert.equal(result, null);
});

void test("parseGoRuntimeMetadata rejects an invalid file-table reference", async () => {
  const fixture = createGoRuntimeFixture("go1.20+");
  const cuAddress = new DataView(fixture.moduleBytes.buffer).getBigUint64(4 * 8, true);
  const cuOffset = Number(cuAddress - fixture.pcHeaderAddress);
  new DataView(fixture.headerBytes.buffer).setUint32(cuOffset, 3, true);

  const result = await parseGoRuntimeMetadata(
    fixture.image,
    fixture.pcHeaderAddress,
    fixture.moduleDataAddress
  );

  assert.equal(result, null);
});

void test("parseGoRuntimeMetadata rejects a malformed function name", async () => {
  const fixture = createGoRuntimeFixture("go1.20+");
  const namesAddress = new DataView(fixture.moduleBytes.buffer).getBigUint64(8, true);
  const namesOffset = Number(namesAddress - fixture.pcHeaderAddress);
  fixture.headerBytes.fill(0x61, namesOffset, namesOffset + 23);

  const result = await parseGoRuntimeMetadata(
    fixture.image,
    fixture.pcHeaderAddress,
    fixture.moduleDataAddress
  );

  assert.equal(result, null);
});

void test("parseGoRuntimeMetadata rejects functab ranges outside executable text", async () => {
  const fixture = createGoRuntimeFixture("go1.20+");
  fixture.regions[0]!.executable = false;

  const result = await parseGoRuntimeMetadata(
    fixture.image,
    fixture.pcHeaderAddress,
    fixture.moduleDataAddress
  );

  assert.equal(result, null);
});

void test("parseGoRuntimeMetadata parses the 32-bit Go 1.20 layout", async () => {
  const fixture = createGoRuntimeFixture("go1.20+", 4, 0x0040_0000n);

  const result = await parseGoRuntimeMetadata(
    fixture.image,
    fixture.pcHeaderAddress,
    fixture.moduleDataAddress
  );

  assert.equal(result?.pointerSize, 4);
  assert.deepEqual(result?.functions.map(fn => fn.name), ["runtime.main", "main.main"]);
});

void test("parseGoPcHeader rejects malformed counts, offsets, and truncation", async () => {
  const zeroFunctions = createGoRuntimeFixture("go1.20+");
  new DataView(zeroFunctions.headerBytes.buffer).setBigUint64(8, 0n, true);
  const excessiveFiles = createGoRuntimeFixture("go1.20+");
  new DataView(excessiveFiles.headerBytes.buffer).setBigUint64(16, 1_000_001n, true);
  const unorderedOffsets = createGoRuntimeFixture("go1.20+");
  const unorderedView = new DataView(unorderedOffsets.headerBytes.buffer);
  unorderedView.setBigUint64(40, unorderedView.getBigUint64(32, true), true);
  const excessiveOffset = createGoRuntimeFixture("go1.20+");
  new DataView(excessiveOffset.headerBytes.buffer).setBigUint64(64, 64n * 1024n * 1024n + 1n, true);
  const truncated = createGoRuntimeFixture("go1.20+");
  truncated.regions[1]!.bytes = truncated.headerBytes.slice(0, 12);

  assert.equal(await parseGoPcHeader(zeroFunctions.image, zeroFunctions.pcHeaderAddress), null);
  assert.equal(await parseGoPcHeader(excessiveFiles.image, excessiveFiles.pcHeaderAddress), null);
  assert.equal(await parseGoPcHeader(unorderedOffsets.image, unorderedOffsets.pcHeaderAddress), null);
  assert.equal(await parseGoPcHeader(excessiveOffset.image, excessiveOffset.pcHeaderAddress), null);
  assert.equal(await parseGoPcHeader(truncated.image, truncated.pcHeaderAddress), null);
});

void test("parseGoPcHeader accepts official PC quanta and rejects other values", async () => {
  const quantumTwo = createGoRuntimeFixture("go1.20+");
  quantumTwo.headerBytes[6] = 2;
  const quantumFour = createGoRuntimeFixture("go1.20+");
  quantumFour.headerBytes[6] = 4;
  const invalid = createGoRuntimeFixture("go1.20+");
  invalid.headerBytes[6] = 3;

  assert.ok(await parseGoPcHeader(quantumTwo.image, quantumTwo.pcHeaderAddress));
  assert.ok(await parseGoPcHeader(quantumFour.image, quantumFour.pcHeaderAddress));
  assert.equal(await parseGoPcHeader(invalid.image, invalid.pcHeaderAddress), null);
});

void test("parseGoPcHeader exposes exact counts and table offsets without rereading its prefix", async () => {
  const fixture = createGoRuntimeFixture("go1.20+");
  const reads: Array<{ address: bigint; size: number }> = [];
  const image = {
    ...fixture.image,
    readMapped: async (address: bigint, size: number) => {
      reads.push({ address, size });
      return fixture.image.readMapped(address, size);
    }
  };
  const moduleView = new DataView(fixture.moduleBytes.buffer);

  const header = await parseGoPcHeader(image, fixture.pcHeaderAddress);

  assert.ok(header);
  assert.equal(header.functionCount, 2);
  assert.equal(header.fileCount, 2);
  assert.equal(header.textField, fixture.textAddress);
  assert.deepEqual(header.tableOffsets, [1, 4, 7, 10, 13].map(word =>
    moduleView.getBigUint64(word * 8, true) - fixture.pcHeaderAddress
  ));
  assert.deepEqual(reads, [
    { address: fixture.pcHeaderAddress, size: 8 },
    { address: fixture.pcHeaderAddress + 8n, size: 64 }
  ]);
});
