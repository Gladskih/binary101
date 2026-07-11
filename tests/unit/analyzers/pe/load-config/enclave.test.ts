"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseEnclaveConfiguration } from "../../../../../analyzers/pe/load-config/enclave.js";
import {
  createPeRvaMapping,
  PE32_POINTER_BYTES,
  PE32_PLUS_POINTER_BYTES,
  type PePointerBytes,
  type PeRvaMapping
} from "../../../../../analyzers/pe/load-config/reference-reader.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { expectDefined } from "../../../../helpers/expect-defined.js";

const IMAGE_BASE = 0x140000000n;
const CONFIG_RVA = 0x40;

// Fixture offsets mirror the Windows SDK IMAGE_ENCLAVE_CONFIG32/64 and IMAGE_ENCLAVE_IMPORT.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_enclave_config64
const parseMappedConfiguration = async (
  bytes: Uint8Array,
  pointerBytes: PePointerBytes,
  mapping: PeRvaMapping
) => {
  const warnings: string[] = [];
  const notes: string[] = [];
  const config = await parseEnclaveConfiguration(
    new MockFile(bytes, "enclave.bin"),
    mapping,
    IMAGE_BASE,
    pointerBytes,
    warnings,
    notes,
    IMAGE_BASE + BigInt(CONFIG_RVA)
  );
  return { config, warnings, notes };
};

const parseConfiguration = async (bytes: Uint8Array, pointerBytes: PePointerBytes) =>
  parseMappedConfiguration(
    bytes, pointerBytes, createPeRvaMapping(bytes.length, [], bytes.length, value => value)
  );

const writeImportMatchTypes = (view: DataView, matchTypes: number[]): void => {
  matchTypes.forEach((matchType, index) => {
    view.setUint32(0x100 + index * 80, matchType, true);
  });
};

const splitNameRvaToOffset = (rva: number): number | null => {
  if (rva >= 0x40 && rva < 0x181) return rva;
  if (rva >= 0x181 && rva < 0x183) return 0x300 + rva - 0x181;
  return null;
};

const createSplitNameMapping = (fileSize: number): PeRvaMapping => createPeRvaMapping(
  fileSize,
  [{
    name: { kind: "inline", value: ".s0" },
    virtualAddress: 0x40,
    virtualSize: 0x141,
    sizeOfRawData: 0x141,
    pointerToRawData: 0x40,
    characteristics: 0
  }, {
    name: { kind: "inline", value: ".s1" },
    virtualAddress: 0x181,
    virtualSize: 2,
    sizeOfRawData: 2,
    pointerToRawData: 0x300,
    characteristics: 0
  }],
  0,
  splitNameRvaToOffset
);

void test("parseEnclaveConfiguration decodes a complete 64-bit configuration, import, and name", async () => {
  const bytes = new Uint8Array(0x400).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(CONFIG_RVA, 0x50, true);
  view.setUint32(CONFIG_RVA + 4, 0x4c, true);
  view.setUint32(CONFIG_RVA + 8, 0x01020304, true);
  view.setUint32(CONFIG_RVA + 12, 1, true);
  view.setUint32(CONFIG_RVA + 16, 0x100, true);
  view.setUint32(CONFIG_RVA + 20, 0x50, true);
  view.setBigUint64(CONFIG_RVA + 64, 0x200000n, true);
  view.setUint32(CONFIG_RVA + 56, 0x02030405, true);
  view.setUint32(CONFIG_RVA + 60, 0x03040506, true);
  view.setUint32(CONFIG_RVA + 72, 2, true);
  view.setUint32(CONFIG_RVA + 76, 1, true);
  view.setUint32(0x100, 2, true);
  view.setUint32(0x104, 7, true);
  view.setUint32(0x148, 0x180, true);
  view.setUint32(0x14c, 0x04050607, true);
  bytes.set(new TextEncoder().encode("enclave-dependency\0"), 0x180);

  const { config, warnings, notes } = await parseConfiguration(bytes, PE32_PLUS_POINTER_BYTES);
  const enclave = expectDefined(config);
  const imported = expectDefined(enclave.imports[0]);

  assert.equal(enclave.enclaveSize, 0x200000n);
  assert.equal(enclave.numberOfThreads, 2);
  assert.equal(enclave.enclaveFlags, 1);
  assert.equal(enclave.minimumRequiredConfigSize, 0x4c);
  assert.equal(enclave.policyFlags, 0x01020304);
  assert.equal(enclave.numberOfImports, 1);
  assert.equal(enclave.importListRva, 0x100);
  assert.equal(enclave.importEntrySize, 0x50);
  assert.equal(enclave.imageVersion, 0x02030405);
  assert.equal(enclave.securityVersion, 0x03040506);
  assert.equal(imported.matchType, "AUTHOR_ID");
  assert.equal(imported.minimumSecurityVersion, 7);
  assert.equal(imported.reserved, 0x04050607);
  assert.equal(imported.name, "enclave-dependency");
  assert.deepEqual(warnings, []);
  assert.deepEqual(notes, []);
});

void test("parseEnclaveConfiguration preserves a valid minimum-size PE32 prefix", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(CONFIG_RVA, 72, true);
  view.setUint32(CONFIG_RVA + 64, 0x2000, true);
  view.setUint32(CONFIG_RVA + 68, 3, true);

  const { config } = await parseConfiguration(bytes, PE32_POINTER_BYTES);

  assert.equal(config?.enclaveSize, 0x2000n);
  assert.equal(config?.numberOfThreads, 3);
  assert.equal(config?.enclaveFlags, undefined);
});

void test("parseEnclaveConfiguration rejects undersized structures and import entries", async () => {
  const undersizedBytes = new Uint8Array(0x100).fill(0);
  new DataView(undersizedBytes.buffer).setUint32(CONFIG_RVA, 60, true);
  const importBytes = new Uint8Array(0x200).fill(0);
  const importView = new DataView(importBytes.buffer);
  importView.setUint32(CONFIG_RVA, 80, true);
  importView.setUint32(CONFIG_RVA + 12, 1, true);
  importView.setUint32(CONFIG_RVA + 16, 0x100, true);
  importView.setUint32(CONFIG_RVA + 20, 79, true);

  const undersized = await parseConfiguration(undersizedBytes, PE32_PLUS_POINTER_BYTES);
  const badImport = await parseConfiguration(importBytes, PE32_PLUS_POINTER_BYTES);

  assert.equal(undersized.config, null);
  assert.ok(undersized.warnings.some(warning => warning.includes("Size 0x3c is too small")));
  assert.deepEqual(badImport.config?.imports, []);
  assert.ok(badImport.warnings.some(warning => warning.includes("ImportEntrySize 79")));
});

void test("parseEnclaveConfiguration reports missing and truncated import tables", async () => {
  const missingBytes = new Uint8Array(0x100).fill(0);
  const missingView = new DataView(missingBytes.buffer);
  missingView.setUint32(CONFIG_RVA, 80, true);
  missingView.setUint32(CONFIG_RVA + 12, 1, true);
  missingView.setUint32(CONFIG_RVA + 20, 80, true);
  const truncatedBytes = new Uint8Array(0x120).fill(0);
  const truncatedView = new DataView(truncatedBytes.buffer);
  truncatedView.setUint32(CONFIG_RVA, 80, true);
  truncatedView.setUint32(CONFIG_RVA + 12, 2, true);
  truncatedView.setUint32(CONFIG_RVA + 16, 0x100, true);
  truncatedView.setUint32(CONFIG_RVA + 20, 80, true);

  const missing = await parseConfiguration(missingBytes, PE32_PLUS_POINTER_BYTES);
  const truncated = await parseConfiguration(truncatedBytes, PE32_PLUS_POINTER_BYTES);

  assert.ok(missing.warnings.some(warning => warning.includes("no valid table RVA")));
  assert.ok(truncated.warnings.some(warning => warning.includes("import list is truncated")));
});

void test("parseEnclaveConfiguration bounds names by their raw-mapped span", async () => {
  const bytes = new Uint8Array(0x181).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(CONFIG_RVA, 80, true);
  view.setUint32(CONFIG_RVA + 12, 1, true);
  view.setUint32(CONFIG_RVA + 16, 0x100, true);
  view.setUint32(CONFIG_RVA + 20, 80, true);
  view.setUint32(0x148, 0x180, true);
  bytes[0x180] = 0x41;

  const { config, warnings } = await parseConfiguration(bytes, PE32_PLUS_POINTER_BYTES);

  assert.equal(config?.imports[0]?.name, "A");
  assert.ok(warnings.some(warning => warning.includes("name is not null-terminated")));
});

void test("parseEnclaveConfiguration reports declared extension bytes outside raw data", async () => {
  const bytes = new Uint8Array(0x90).fill(0);
  new DataView(bytes.buffer).setUint32(CONFIG_RVA, 0x80, true);

  const { config, warnings, notes } = await parseConfiguration(bytes, PE32_PLUS_POINTER_BYTES);

  assert.equal(config?.size, 0x80);
  assert.ok(warnings.some(warning => warning.includes("declared Size extends beyond raw file data")));
  assert.ok(notes.some(note => note.includes("48 extension bytes")));
});

void test("parseEnclaveConfiguration decodes every documented import match type", async () => {
  const bytes = new Uint8Array(0x400).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(CONFIG_RVA, 80, true);
  view.setUint32(CONFIG_RVA + 12, 5, true);
  view.setUint32(CONFIG_RVA + 16, 0x100, true);
  view.setUint32(CONFIG_RVA + 20, 80, true);
  writeImportMatchTypes(view, [0, 1, 3, 4, 5]);

  const { config } = await parseConfiguration(bytes, PE32_PLUS_POINTER_BYTES);

  assert.deepEqual(config?.imports.map(entry => entry.matchType), [
    "NONE", "UNIQUE_ID", "FAMILY_ID", "IMAGE_ID", "UNKNOWN"
  ]);
  assert.deepEqual(config?.imports.map(entry => entry.name), [
    undefined, undefined, undefined, undefined, undefined
  ]);
});

void test("parseEnclaveConfiguration follows an import name across adjacent RVA sections", async () => {
  const bytes = new Uint8Array(0x320).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(CONFIG_RVA, 80, true);
  view.setUint32(CONFIG_RVA + 12, 1, true);
  view.setUint32(CONFIG_RVA + 16, 0x100, true);
  view.setUint32(CONFIG_RVA + 20, 80, true);
  view.setUint32(0x148, 0x180, true);
  bytes[0x180] = 0x41;
  bytes.set([0x42, 0], 0x300);
  const result = await parseMappedConfiguration(
    bytes,
    PE32_PLUS_POINTER_BYTES,
    createSplitNameMapping(bytes.length)
  );

  assert.equal(result.config?.imports[0]?.name, "AB");
  assert.deepEqual(result.warnings, []);
});

void test("parseEnclaveConfiguration reports invalid configuration and import-name pointers", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(CONFIG_RVA, 80, true);
  view.setUint32(CONFIG_RVA + 12, 1, true);
  view.setUint32(CONFIG_RVA + 16, 0x100, true);
  view.setUint32(CONFIG_RVA + 20, 80, true);
  view.setUint32(0x148, 0x300, true);
  const missingName = await parseConfiguration(bytes, PE32_PLUS_POINTER_BYTES);
  const invalidWarnings: string[] = [];
  const invalid = await parseEnclaveConfiguration(
    new MockFile(bytes, "invalid-enclave.bin"),
    createPeRvaMapping(bytes.length, [], bytes.length, value => value),
    IMAGE_BASE,
    PE32_PLUS_POINTER_BYTES,
    invalidWarnings,
    [],
    IMAGE_BASE - 1n
  );

  assert.ok(missingName.notes.some(note => note ===
    "LOAD_CONFIG: Enclave import 0 name RVA 0x300 is not backed by raw file data."));
  assert.equal(invalid, null);
  assert.deepEqual(invalidWarnings, [
    "LOAD_CONFIG: EnclaveConfigurationPointer pointer 0x13fffffff is not a valid VA."
  ]);
});
