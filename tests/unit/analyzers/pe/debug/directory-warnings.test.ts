"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";
import { IMAGE_FILE_MACHINE_AMD64 } from "../../../../../analyzers/coff/machine.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE = 28;

void test("parseDebugDirectory warns when entry Characteristics is non-zero", async () => {
  const debugRva = 0x20;
  const bytes = new Uint8Array(0x80).fill(0);
  const view = new DataView(bytes.buffer);
  // Microsoft PE format: IMAGE_DEBUG_DIRECTORY.Characteristics is reserved and must be 0.
  view.setUint32(debugRva, 1, true);

  const result = await parseDebugDirectory(
    new MockFile(bytes, "debug-characteristics.bin"),
    [{ name: "DEBUG", rva: debugRva, size: IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE }],
    value => value,
    IMAGE_FILE_MACHINE_AMD64
  );

  assert.equal(result.entries[0]?.characteristics, 1);
  assert.ok(result.warning?.includes("Characteristics field is non-zero"));
});
