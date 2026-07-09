"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBinaryType } from "../../../../analyzers/index.js";
import { MockFile } from "../../../helpers/mock-file.js";
import {
  createSqliteFile,
  createSqliteWalIndexSharedMemoryFile
} from "../../../fixtures/sqlite-fixtures.js";

const fromAscii = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "ascii"));
// Linux initramfs buffer format: newc/crc CPIO magic strings.
const CPIO_NEWC_MAGIC = "070701";
const CPIO_CRC_MAGIC = "070702";
// Linux initramfs buffer format: after magic, newc/crc headers contain thirteen
// 8-hex-digit fields.
const CPIO_HEADER_FIELD_COUNT = 13;
const CPIO_HEADER_FIELD_HEX_DIGITS = 8;

const fromUtf16Le = (text: string): Uint8Array => {
  const bytes = new Uint8Array(2 + text.length * 2);
  bytes[0] = 0xff;
  bytes[1] = 0xfe;
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < text.length; index += 1) {
    view.setUint16(2 + index * 2, text.charCodeAt(index), true);
  }
  return bytes;
};

const createCpioFixedHeader = (magic: string): Uint8Array =>
  fromAscii(magic + "0".repeat(CPIO_HEADER_FIELD_COUNT * CPIO_HEADER_FIELD_HEX_DIGITS));

const createTerminfoEntry = (nameList: string): Uint8Array => {
  const names = fromAscii(`${nameList}\0`);
  const booleanCount = 1;
  const numberCount = 1;
  const stringCount = 1;
  const stringTableSize = 4;
  const afterBooleans = 12 + names.length + booleanCount;
  const numbersOffset = afterBooleans + (afterBooleans % 2);
  const bytes = new Uint8Array(numbersOffset + numberCount * 2 + stringCount * 2 + stringTableSize);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x011a, true);
  view.setUint16(2, names.length, true);
  view.setUint16(4, booleanCount, true);
  view.setUint16(6, numberCount, true);
  view.setUint16(8, stringCount, true);
  view.setUint16(10, stringTableSize, true);
  bytes.set(names, 12);
  return bytes;
};

void test("detectBinaryType recognises animated cursors (ANI)", async () => {
  const bytes = new Uint8Array([
    0x52, 0x49, 0x46, 0x46,
    0x24, 0x00, 0x00, 0x00,
    0x41, 0x43, 0x4f, 0x4e
  ]);
  const label = await detectBinaryType(new MockFile(bytes, "aero_busy.ani", "application/octet-stream"));
  assert.strictEqual(label, "Windows animated cursor (ANI)");
});

void test("detectBinaryType reports large cursor files from ICO/CUR headers", async () => {
  const cursor = new Uint8Array(22);
  const view = new DataView(cursor.buffer);
  view.setUint16(0, 0, true);
  view.setUint16(2, 2, true);
  view.setUint16(4, 1, true);
  cursor[6] = 128;
  cursor[7] = 128;
  view.setUint16(10, 25, true);
  view.setUint32(14, 128 * 1024, true);
  view.setUint32(18, 22, true);
  const label = await detectBinaryType(new MockFile(cursor, "large.cur"));
  assert.strictEqual(label, "ICO/CUR icon image");
});

void test("detectBinaryType reports compiled terminfo entries", async () => {
  const file = new MockFile(createTerminfoEntry("vt100|DEC VT100"), "vt100");
  const label = await detectBinaryType(file);
  assert.strictEqual(label, 'Compiled terminfo entry "vt100" (terminal capability database)');
});

void test("detectBinaryType reports Windows INF setup scripts", async () => {
  const inf = ["; sample INF", "[Version]", 'Signature="$Windows NT$"', "Class=System"].join("\r\n");
  const label = await detectBinaryType(new MockFile(fromUtf16Le(inf), "sample.inf"));
  assert.strictEqual(label, "Windows setup information file (INF, driver/install directives)");
});

void test("detectBinaryType reports PEM armor blocks", async () => {
  const pem = ["-----BEGIN CERTIFICATE-----", "QUJD", "-----END CERTIFICATE-----"].join("\n");
  const label = await detectBinaryType(new MockFile(fromAscii(pem), "cert.pem"));
  assert.strictEqual(label, "PEM armor block (certificate/key text encoding)");
});

void test("detectBinaryType reports PostScript documents", async () => {
  const file = new MockFile(fromAscii("%!PS-Adobe-3.0\n%%Title: sample"), "sample.ps");
  assert.strictEqual(
    await detectBinaryType(file),
    "PostScript document (page description program)"
  );
});

void test("detectBinaryType reports PostScript Printer Description files", async () => {
  const file = new MockFile(fromAscii("*PPD-Adobe: \"4.3\"\n*FormatVersion: \"4.3\""), "printer.ppd");
  assert.strictEqual(
    await detectBinaryType(file),
    "PostScript Printer Description file (PPD printer driver metadata)"
  );
});

void test("detectBinaryType reports GNU gettext message catalogs", async () => {
  const file = new MockFile(new Uint8Array([0xde, 0x12, 0x04, 0x95]), "messages.mo");
  assert.strictEqual(await detectBinaryType(file), "GNU gettext message catalog (MO translations)");
});

void test("detectBinaryType reports Linux initramfs CPIO archives", async () => {
  // Linux initramfs buffer format accepts newc magic "070701" and crc magic "070702".
  assert.strictEqual(
    await detectBinaryType(new MockFile(createCpioFixedHeader(CPIO_NEWC_MAGIC), "initrd.img")),
    "Linux initramfs (CPIO newc archive)"
  );
  assert.strictEqual(
    await detectBinaryType(new MockFile(createCpioFixedHeader(CPIO_CRC_MAGIC), "initramfs.img")),
    "Linux initramfs (CPIO crc archive)"
  );
});

void test("detectBinaryType reports Windows Application Compatibility databases", async () => {
  const bytes = new Uint8Array(16);
  bytes.set([0x03, 0x00, 0x00, 0x00]);
  bytes.set(fromAscii("sdbf"), 8);
  const label = await detectBinaryType(new MockFile(bytes, "sysmain.sdb"));
  assert.strictEqual(label, "Windows Application Compatibility Database (SDB shim database)");
});

void test("detectBinaryType reports font formats", async () => {
  const cases = [
    { bytes: [0x00, 0x01, 0x00, 0x00], name: "font.ttf", label: "TrueType/OpenType font (sfnt glyph outlines)" },
    { bytes: [0x77, 0x4f, 0x46, 0x32], name: "font.woff2", label: "Web Open Font Format 2 font (WOFF2 compressed web font)" },
    { bytes: [0x77, 0x4f, 0x46, 0x46], name: "font.woff", label: "Web Open Font Format font (WOFF compressed web font)" }
  ];
  for (const item of cases) {
    const label = await detectBinaryType(new MockFile(new Uint8Array(item.bytes), item.name));
    assert.strictEqual(label, item.label);
  }
});

void test("detectBinaryType reports CPython bytecode cache files", async () => {
  const bytes = new Uint8Array(16);
  bytes.set([0xcb, 0x0d, 0x0d, 0x0a]);
  const label = await detectBinaryType(new MockFile(bytes, "module.cpython-312.pyc"));
  assert.strictEqual(label, "Python bytecode cache (PYC compiled module)");
});

void test("detectBinaryType reports SQLite formats", async () => {
  assert.strictEqual(await detectBinaryType(createSqliteFile()), "SQLite 3.x database");
  assert.strictEqual(
    await detectBinaryType(createSqliteWalIndexSharedMemoryFile()),
    "SQLite WAL-index shared-memory file"
  );
});
