"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseGoPcHeader, type ModuleDataPrefix } from "../../../../analyzers/go-runtime/parser.js";
import {
  parseGoFunctions,
  parseGoFunctionTable,
  validateGoFileTables
} from "../../../../analyzers/go-runtime/tables.js";
import { createGoRuntimeFixture } from "../../../fixtures/go-runtime.js";

const modulePrefix = (
  fixture: ReturnType<typeof createGoRuntimeFixture>,
  fileLength: number
): ModuleDataPrefix => {
  const view = new DataView(fixture.moduleBytes.buffer);
  const slice = (word: number, length = Number(view.getBigUint64((word + 1) * 8, true))) => ({
    address: view.getBigUint64(word * 8, true),
    length,
    capacity: length
  });
  return {
    slices: [
      slice(1),
      slice(4),
      slice(7, fileLength),
      slice(10),
      slice(13),
      slice(16)
    ],
    findFuncTable: fixture.pcHeaderAddress,
    minPc: fixture.textAddress,
    maxPc: fixture.textAddress + 0x40n,
    text: fixture.textAddress,
    textEnd: fixture.textAddress + 0x40n
  };
};

void test("validateGoFileTables accepts linker alignment padding", async () => {
  const fixture = createGoRuntimeFixture("go1.20+");
  const header = await parseGoPcHeader(fixture.image, fixture.pcHeaderAddress);
  assert.ok(header);

  // cmd/link addGeneratedSym rounds table symbols to the target pointer size.
  const valid = await validateGoFileTables(fixture.image, header, modulePrefix(fixture, 32));
  const excessive = await validateGoFileTables(fixture.image, header, modulePrefix(fixture, 40));

  assert.equal(valid, true);
  assert.equal(excessive, false);
});

void test("parseGoFunctionTable accepts ELF-style extents without moduledata", async () => {
  const fixture = createGoRuntimeFixture("go1.20+");
  const header = await parseGoPcHeader(fixture.image, fixture.pcHeaderAddress);
  assert.ok(header);
  const prefix = modulePrefix(fixture, 32);
  assert.deepEqual(await parseGoFunctionTable(fixture.image, header, prefix.slices[0]!,
    prefix.slices[4]!, fixture.textAddress), [
    { name: "runtime.main", start: fixture.textAddress, end: fixture.textAddress + 32n },
    { name: "main.main", start: fixture.textAddress + 32n, end: fixture.textAddress + 64n }
  ]);
});

for (const length of [-1, 0, 1, Number.MAX_SAFE_INTEGER]) {
  void test(`parseGoFunctionTable rejects invalid extent ${length}`, async () => {
    const fixture = createGoRuntimeFixture("go1.20+");
    const header = await parseGoPcHeader(fixture.image, fixture.pcHeaderAddress);
    assert.ok(header);
    const prefix = modulePrefix(fixture, 32);
    assert.equal(await parseGoFunctionTable(fixture.image, header,
      { ...prefix.slices[0]!, length }, prefix.slices[4]!, fixture.textAddress), null);
    assert.equal(await parseGoFunctionTable(fixture.image, header, prefix.slices[0]!,
      { ...prefix.slices[4]!, length }, fixture.textAddress), null);
  });
}

for (const offset of [0, 19, 33, 40]) {
  void test(`parseGoFunctionTable rejects metadata offset ${offset}`, async () => {
    const fixture = createGoRuntimeFixture("go1.20+");
    const header = await parseGoPcHeader(fixture.image, fixture.pcHeaderAddress);
    assert.ok(header);
    const prefix = modulePrefix(fixture, 32);
    // Modern functab pairs contain two uint32 words; table with sentinel is 20 bytes.
    new DataView(fixture.headerBytes.buffer).setUint32(Number(header.tableOffsets[4]!) + 4, offset, true);
    assert.equal(await parseGoFunctionTable(fixture.image, header, prefix.slices[0]!,
      prefix.slices[4]!, fixture.textAddress), null);
  });
}

void test("table parsers reject absent slice descriptors", async () => {
  const fixture = createGoRuntimeFixture("go1.20+");
  const header = await parseGoPcHeader(fixture.image, fixture.pcHeaderAddress);
  assert.ok(header);
  const fileLength = Number(new DataView(fixture.moduleBytes.buffer).getBigUint64(8 * 8, true));
  const empty = { ...modulePrefix(fixture, fileLength), slices: [] };

  assert.equal(await validateGoFileTables(fixture.image, header, empty), false);
  assert.equal(await parseGoFunctions(fixture.image, header, empty), null);
});

void test("parseGoFunctions rejects unavailable name and functab bytes", async () => {
  const fixture = createGoRuntimeFixture("go1.20+");
  const header = await parseGoPcHeader(fixture.image, fixture.pcHeaderAddress);
  assert.ok(header);
  const fileLength = Number(new DataView(fixture.moduleBytes.buffer).getBigUint64(8 * 8, true));
  const missingNames = modulePrefix(fixture, fileLength);
  missingNames.slices[0]!.address += 0x1000n;
  const missingTable = modulePrefix(fixture, fileLength);
  missingTable.slices[4]!.address += 0x1000n;

  assert.equal(await parseGoFunctions(fixture.image, header, missingNames), null);
  assert.equal(await parseGoFunctions(fixture.image, header, missingTable), null);
});
