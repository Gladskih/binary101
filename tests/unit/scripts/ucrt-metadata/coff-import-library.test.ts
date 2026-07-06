"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { IMAGE_FILE_MACHINE_AMD64 } from "../../../../analyzers/coff/machine.js";
import { readCoffImportLibraryEntries } from "../../../../scripts/ucrt-metadata/coff-import-library.js";

const encoder = new TextEncoder();

const ascii = (text: string): Uint8Array => encoder.encode(text);

const decimalField = (value: number, width: number): string =>
  String(value).padEnd(width, " ");

const archiveMember = (name: string, data: Uint8Array): Uint8Array => {
  const header = ascii(
    name.padEnd(16, " ") +
    decimalField(0, 12) +
    decimalField(0, 6) +
    decimalField(0, 6) +
    decimalField(0, 8) +
    decimalField(data.byteLength, 10) +
    "`\n"
  );
  const padding = data.byteLength % 2 ? new Uint8Array([0x0a]) : new Uint8Array();
  const bytes = new Uint8Array(header.byteLength + data.byteLength + padding.byteLength);
  bytes.set(header, 0);
  bytes.set(data, header.byteLength);
  bytes.set(padding, header.byteLength + data.byteLength);
  return bytes;
};

const shortImportObject = (symbolName: string, dllName: string): Uint8Array => {
  const strings = ascii(`${symbolName}\0${dllName}\0`);
  const bytes = new Uint8Array(20 + strings.byteLength);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x0000, true);
  view.setUint16(2, 0xffff, true);
  view.setUint16(4, 0, true);
  view.setUint16(6, IMAGE_FILE_MACHINE_AMD64, true);
  view.setUint32(8, 0, true);
  view.setUint32(12, strings.byteLength, true);
  view.setUint16(16, 7, true);
  view.setUint16(18, 0, true);
  bytes.set(strings, 20);
  return bytes;
};

void test("readCoffImportLibraryEntries reads short import object members", () => {
  const member = archiveMember("/", new Uint8Array());
  const importMember = archiveMember("printf/", shortImportObject("printf", "api-ms-win-crt-stdio-l1-1-0.dll"));
  const archive = new Uint8Array(8 + member.byteLength + importMember.byteLength);
  archive.set(ascii("!<arch>\n"), 0);
  archive.set(member, 8);
  archive.set(importMember, 8 + member.byteLength);

  assert.deepEqual(readCoffImportLibraryEntries(archive), [{
    module: "api-ms-win-crt-stdio-l1-1-0.dll",
    exportName: "printf",
    symbolName: "printf",
    ordinalOrHint: 7
  }]);
});
