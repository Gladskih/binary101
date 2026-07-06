"use strict";

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { validateNoPeLegacyCoffSymbolRecords } from "../../../../scripts/pe-disassembly-samples/pe-coff-symbols.js";

const createPeBytes = (pointerToSymbolTable: number, symbolCount: number): Buffer => {
  // PE fixture offsets follow IMAGE_DOS_HEADER.e_lfanew and IMAGE_FILE_HEADER:
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
  const peOffset = 0x80;
  const bytes = Buffer.alloc(peOffset + 24);
  bytes.write("MZ", 0, "ascii");
  bytes.writeUInt32LE(peOffset, 0x3c);
  bytes.write("PE\0\0", peOffset, "ascii");
  bytes.writeUInt32LE(pointerToSymbolTable, peOffset + 4 + 8);
  bytes.writeUInt32LE(symbolCount, peOffset + 4 + 12);
  return bytes;
};

const withTempFile = async (bytes: Buffer, action: (path: string) => Promise<void>): Promise<void> => {
  const directory = await mkdtemp(join(tmpdir(), "binary101-pe-coff-symbols-"));
  try {
    const path = join(directory, "sample.exe");
    await writeFile(path, bytes);
    await action(path);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
};

void test("validateNoPeLegacyCoffSymbolRecords accepts a PE image without COFF symbols", async () => {
  await withTempFile(createPeBytes(0, 0), async path => {
    const result = await validateNoPeLegacyCoffSymbolRecords(path);

    assert.equal(result.error, null);
    assert.equal(result.header?.pointerToSymbolTable, 0);
    assert.deepEqual(result.warnings, []);
  });
});

void test("validateNoPeLegacyCoffSymbolRecords warns on a stale empty COFF pointer", async () => {
  await withTempFile(createPeBytes(0x1234, 0), async path => {
    const result = await validateNoPeLegacyCoffSymbolRecords(path);
    const bytes = await readFile(path);

    assert.equal(result.error, null);
    assert.match(result.warnings.join(" "), /zero.*records/);
    assert.equal(bytes.readUInt32LE(0x80 + 4 + 8), 0x1234);
  });
});

void test("validateNoPeLegacyCoffSymbolRecords rejects real COFF symbols", async () => {
  await withTempFile(createPeBytes(0x1234, 5), async path => {
    const result = await validateNoPeLegacyCoffSymbolRecords(path);
    const bytes = await readFile(path);

    assert.match(result.error ?? "", /COFF symbol table/);
    assert.equal(bytes.readUInt32LE(0x80 + 4 + 8), 0x1234);
  });
});

void test("validateNoPeLegacyCoffSymbolRecords reports truncated files", async () => {
  await withTempFile(Buffer.from("MZ", "ascii"), async path => {
    const result = await validateNoPeLegacyCoffSymbolRecords(path);

    assert.match(result.error ?? "", /too small/);
    assert.match(result.warnings.join(" "), /too small/);
  });
});

void test("validateNoPeLegacyCoffSymbolRecords reports missing files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "binary101-pe-coff-missing-"));
  try {
    const result = await validateNoPeLegacyCoffSymbolRecords(join(directory, "missing.exe"));

    assert.match(result.error ?? "", /Could not open/);
    assert.match(result.warnings.join(" "), /Could not open/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
