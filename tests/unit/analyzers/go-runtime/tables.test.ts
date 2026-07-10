"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseGoPcHeader, type ModuleDataPrefix } from "../../../../analyzers/go-runtime/parser.js";
import {
  parseGoFunctions,
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
