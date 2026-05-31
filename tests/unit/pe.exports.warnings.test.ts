"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createFileRangeReader,
  type FileRangeReader
} from "../../analyzers/file-range-reader.js";
import { parseExportDirectory } from "../../analyzers/pe/directories/exports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();
const IMAGE_EXPORT_DIRECTORY_SIZE = 40;
const EXPORT_DIRECTORY_RVA = 0x20;
const EXPORT_SORT_WARNING =
  "Export name pointer table is not sorted lexically; the PE loader expects it to support binary search.";
const EXPORT_FLAGS_WARNING = "Export directory flags are reserved and must be zero.";

const parseExportFixture = (
  bytes: Uint8Array | File | FileRangeReader,
  directory: { rva: number; size: number },
  rvaToOff: (rva: number) => number | null = value => value
) => parseExportDirectory(
  bytes instanceof Uint8Array
    ? new MockFile(bytes)
    : "read" in bytes
      ? bytes
      : createFileRangeReader(bytes, 0, bytes.size, 0),
  [{ name: "EXPORT", ...directory }],
  rvaToOff
);

const createNamedExportsFixture = (names: [string, string]): Uint8Array => {
  const bytes = new Uint8Array(0x200).fill(0);
  const view = new DataView(bytes.buffer);
  const functionTableRva = 0x80;
  const nameTableRva = 0x90;
  const ordinalTableRva = 0xa0;
  const firstNameRva = 0xc0;
  const secondNameRva = 0xd0;
  view.setUint32(EXPORT_DIRECTORY_RVA + 16, 1, true);
  view.setUint32(EXPORT_DIRECTORY_RVA + 20, 2, true);
  view.setUint32(EXPORT_DIRECTORY_RVA + 24, 2, true);
  view.setUint32(EXPORT_DIRECTORY_RVA + 28, functionTableRva, true);
  view.setUint32(EXPORT_DIRECTORY_RVA + 32, nameTableRva, true);
  view.setUint32(EXPORT_DIRECTORY_RVA + 36, ordinalTableRva, true);
  view.setUint32(functionTableRva, 0x1000, true);
  view.setUint32(functionTableRva + 4, 0x2000, true);
  view.setUint32(nameTableRva, firstNameRva, true);
  view.setUint32(nameTableRva + 4, secondNameRva, true);
  view.setUint16(ordinalTableRva, 0, true);
  view.setUint16(ordinalTableRva + 2, 1, true);
  encoder.encodeInto(`${names[0]}\0`, new Uint8Array(bytes.buffer, firstNameRva));
  encoder.encodeInto(`${names[1]}\0`, new Uint8Array(bytes.buffer, secondNameRva));
  return bytes;
};

void test("parseExportDirectory warns when export flags are non-zero", async () => {
  const directoryRva = 0x10;
  const bytes = new Uint8Array(directoryRva + IMAGE_EXPORT_DIRECTORY_SIZE).fill(0);
  new DataView(bytes.buffer).setUint32(directoryRva, 1, true);

  const result = expectDefined(await parseExportFixture(bytes, {
    rva: directoryRva,
    size: IMAGE_EXPORT_DIRECTORY_SIZE
  }));

  assert.ok(result.issues.includes(EXPORT_FLAGS_WARNING));
});

void test("parseExportDirectory accepts zero export flags", async () => {
  const directoryRva = 0x10;
  const bytes = new Uint8Array(directoryRva + IMAGE_EXPORT_DIRECTORY_SIZE).fill(0);
  const result = expectDefined(await parseExportFixture(bytes, {
    rva: directoryRva,
    size: IMAGE_EXPORT_DIRECTORY_SIZE
  }));

  assert.ok(!result.issues.includes(EXPORT_FLAGS_WARNING));
});

void test("parseExportDirectory warns when export names are not sorted lexically", async () => {
  const result = expectDefined(await parseExportFixture(
    createNamedExportsFixture(["B", "A"]),
    { rva: EXPORT_DIRECTORY_RVA, size: IMAGE_EXPORT_DIRECTORY_SIZE }
  ));

  assert.ok(result.issues.includes(EXPORT_SORT_WARNING));
});

void test("parseExportDirectory accepts lexically sorted export names", async () => {
  const result = expectDefined(await parseExportFixture(
    createNamedExportsFixture(["A", "B"]),
    { rva: EXPORT_DIRECTORY_RVA, size: IMAGE_EXPORT_DIRECTORY_SIZE }
  ));

  assert.ok(!result.issues.includes(EXPORT_SORT_WARNING));
});

void test("parseExportDirectory does not sort-check truncated export names", async () => {
  const bytes = createNamedExportsFixture(["B", "A"]);
  bytes[0xd1] = 0x41;
  bytes[0xd2] = 0x41;

  const result = expectDefined(await parseExportFixture(bytes.slice(0, 0xd3), {
    rva: EXPORT_DIRECTORY_RVA,
    size: IMAGE_EXPORT_DIRECTORY_SIZE
  }));

  assert.ok(result.issues.includes("Export name string truncated."));
  assert.ok(!result.issues.includes(EXPORT_SORT_WARNING));
});
