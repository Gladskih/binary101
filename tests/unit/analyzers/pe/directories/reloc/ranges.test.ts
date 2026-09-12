import assert from "node:assert/strict";
import { test } from "node:test";
import { parseBaseRelocations } from "../../../../../../analyzers/pe/directories/reloc.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

const relocationFile = (): Uint8Array => {
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  // PE format, Base Relocation Block: 8-byte header and two WORD entries.
  view.setUint32(16, 0x2000, true);
  view.setUint32(20, 12, true);
  view.setUint16(24, 0x3001, true);
  view.setUint16(26, 0x3002, true);
  return bytes;
};

void test("relocations retain complete entries before a truncated tail", async () => {
  const parsed = await parseBaseRelocations(new MockFile(relocationFile().slice(0, 26)),
    [{ name: "BASERELOC", rva: 16, size: 12 }], rva => rva);
  assert.deepEqual(parsed?.blocks[0]?.entries, [{ type: 3, offset: 1 }]);
  assert.ok(parsed?.warnings?.length);
});

void test("relocations do not wrap overflowing directory RVAs into headers", async () => {
  const bytes = relocationFile();
  bytes.set(bytes.subarray(24, 28), 0);
  // PE RVAs are DWORDs; a header at 2^32 - 8 leaves no address space for entries.
  const parsed = await parseBaseRelocations(new MockFile(bytes),
    [{ name: "BASERELOC", rva: 0xfffffff8, size: 12 }],
    rva => rva >= 0xfffffff8 ? 16 + rva - 0xfffffff8 : rva < 4 ? rva : null);
  assert.equal(parsed?.totalEntries, 0);
  assert.ok(parsed?.warnings?.length);
});

void test("relocations validate the second byte of every WORD", async () => {
  const parsed = await parseBaseRelocations(new MockFile(relocationFile()),
    [{ name: "BASERELOC", rva: 0x1000, size: 12 }],
    rva => rva >= 0x1000 && rva < 0x100b ? 16 + rva - 0x1000 : null);
  assert.deepEqual(parsed?.blocks[0]?.entries, [{ type: 3, offset: 1 }]);
  assert.ok(parsed?.warnings?.length);
});

void test("HIGHADJ consumes its payload across the bounded read window", async () => {
  // 32768 WORDs fill the reader's 64 KiB window. The payload is the next WORD.
  const bytes = new Uint8Array(8 + (32768 + 2) * 2);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x2000, true);
  view.setUint32(4, bytes.length, true);
  view.setUint16(8 + 32767 * 2, 0x4001, true);
  view.setUint16(8 + 32768 * 2, 0x6000, true); // Payload, never a reserved-type relocation.
  view.setUint16(8 + 32769 * 2, 0x3002, true);
  const parsed = await parseBaseRelocations(new MockFile(bytes),
    [{ name: "BASERELOC", rva: 0x1000, size: bytes.length }], rva => rva - 0x1000);
  assert.equal(parsed?.totalEntries, 32769);
  assert.deepEqual(parsed?.blocks[0]?.entries.slice(-2), [{ type: 4, offset: 1 }, { type: 3, offset: 2 }]);
  assert.equal(parsed?.warnings, undefined);
});

void test("a trailing HIGHADJ reports the missing payload without losing the entry", async () => {
  const bytes = relocationFile();
  new DataView(bytes.buffer).setUint16(26, 0x4002, true);
  const parsed = await parseBaseRelocations(new MockFile(bytes),
    [{ name: "BASERELOC", rva: 16, size: 12 }], rva => rva);
  assert.deepEqual(parsed?.blocks[0]?.entries, [{ type: 3, offset: 1 }, { type: 4, offset: 2 }]);
  assert.match(parsed?.warnings?.join(" ") ?? "", /HIGHADJ.*missing.*second WORD/);
});

void test("relocation directory presence and size errors remain visible", async () => {
  const reader = new MockFile(relocationFile());
  assert.equal(await parseBaseRelocations(reader, [], rva => rva), null);
  assert.equal(await parseBaseRelocations(reader,
    [{ name: "BASERELOC", rva: 0, size: 0 }], rva => rva), null);
  assert.match((await parseBaseRelocations(reader,
    [{ name: "BASERELOC", rva: 0, size: 8 }], rva => rva))?.warnings?.join(" ") ?? "", /RVA is 0/);
  assert.match((await parseBaseRelocations(reader,
    [{ name: "BASERELOC", rva: 16, size: 7 }], rva => rva))?.warnings?.join(" ") ?? "", /smaller.*header/);
});

void test("relocation directory rejects mappings before the file and at EOF", async () => {
  const reader = new MockFile(relocationFile());
  const dirs = [{ name: "BASERELOC", rva: 16, size: 12 }];
  assert.match((await parseBaseRelocations(reader, dirs, () => -1))?.warnings?.join(" ") ?? "",
    /starts outside file data/);
  assert.match((await parseBaseRelocations(reader, dirs, () => reader.size))?.warnings?.join(" ") ?? "",
    /starts outside file data/);
});

void test("relocations distinguish a partial block header from a missing block mapping", async () => {
  const reader = new MockFile(relocationFile());
  const dirs = [{ name: "BASERELOC", rva: 16, size: 20 }];
  const partial = await parseBaseRelocations(reader, dirs, rva => rva);
  const missing = await parseBaseRelocations(reader, dirs, rva => rva < 28 ? rva : null);
  assert.equal(partial?.totalEntries, 2);
  assert.match(partial?.warnings?.join(" ") ?? "", /block header is truncated/);
  assert.equal(missing?.totalEntries, 2);
  assert.match(missing?.warnings?.join(" ") ?? "", /block RVA does not map/);
});

void test("relocations reject undersized block headers", async () => {
  const bytes = relocationFile();
  new DataView(bytes.buffer).setUint32(20, 7, true);
  const parsed = await parseBaseRelocations(new MockFile(bytes),
    [{ name: "BASERELOC", rva: 16, size: 12 }], rva => rva);
  assert.equal(parsed?.totalEntries, 0);
  assert.match(parsed?.warnings?.join(" ") ?? "", /block size is smaller/);
});

void test("relocations report zero-sized terminators and a trailing incomplete header", async () => {
  const bytes = relocationFile();
  const trailing = await parseBaseRelocations(new MockFile(bytes),
    [{ name: "BASERELOC", rva: 16, size: 13 }], rva => rva);
  new DataView(bytes.buffer).setUint32(20, 0, true);
  const zero = await parseBaseRelocations(new MockFile(bytes),
    [{ name: "BASERELOC", rva: 16, size: 12 }], rva => rva);
  assert.equal(trailing?.totalEntries, 2);
  assert.match(trailing?.warnings?.join(" ") ?? "", /ends with a truncated block header/);
  assert.equal(zero?.totalEntries, 0);
  assert.match(zero?.warnings?.join(" ") ?? "", /block size is 0/);
});
