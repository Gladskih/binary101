import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveCoffTableReader } from "../../../../../analyzers/pe/debug/coff-addresses.js";
import { createPeRvaFragments } from "../../../../helpers/pe-rva-fragments.js";

void test("COFF table readers preserve pointer precedence and absolute file offsets", async () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4), 2);
  const table = resolveCoffTableReader(fixture.reader, () => null,
    0x1000, 16, 2, 1, 1);
  assert.ok(table);
  assert.equal(table.offset, 17);
  assert.equal(table.toFileOffset(table.offset), 17);
  assert.equal(table.toFileOffset(-1), null);
  assert.equal(table.toFileOffset(Infinity), null);
  assert.equal((await table.reader.read(table.offset, 1)).getUint8(0), 2);
});

void test("COFF table readers translate payload RVAs and fragmented string offsets", async () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4), 2);
  const table = resolveCoffTableReader(fixture.reader, fixture.mapping,
    0x1000, 0, 4, 0x1001, 1);
  assert.ok(table);
  assert.equal(table.offset, 0);
  assert.equal(table.reader.size, 3);
  assert.deepEqual([...await table.reader.readBytes(0, 3)], [2, 3, 4]);
  assert.equal(table.toFileOffset(1), fixture.mapping(0x1002));
  assert.equal(table.toFileOffset(-1), null);
  assert.equal(table.toFileOffset(table.reader.size), null);
});

void test("COFF table readers keep only the prefix before an unmapped byte", async () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4), 2);
  const table = resolveCoffTableReader(fixture.reader,
    rva => rva === 0x1002 ? null : fixture.mapping(rva),
    0x1000, 0, 4, 1, 4);
  assert.ok(table);
  assert.deepEqual([...await table.reader.readBytes(0, 4)], [2]);
});

void test("COFF table addresses reject unmapped and overflowing RVAs", () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2), 1);
  assert.equal(resolveCoffTableReader(fixture.reader, () => null,
    0x1000, 0, 2, 0x2000, 18), null);
  assert.equal(resolveCoffTableReader(fixture.reader, () => 0,
    0xffffffff, 0, 2, 1, 1), null);
});

void test("COFF table addresses reject invalid file pointers and offset translations", () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2), 1);
  assert.equal(resolveCoffTableReader(fixture.reader, fixture.mapping,
    0x1000, -1, 2, 0, 1), null);
  assert.equal(resolveCoffTableReader(fixture.reader, fixture.mapping,
    0x1000, fixture.reader.size, 2, 0, 1), null);
  assert.equal(resolveCoffTableReader(fixture.reader, fixture.mapping,
    0x1000, 0.5, 2, 0, 1), null);
  const table = resolveCoffTableReader(fixture.reader, fixture.mapping, 0x1000, 16, 2, 0, 1);
  assert.ok(table);
  assert.equal(table.toFileOffset(0), 0);
  assert.equal(table.toFileOffset(0.5), null);
  assert.equal(table.toFileOffset(fixture.reader.size), null);
});

void test("COFF table addresses distinguish zero relative offsets from the legacy header fallback", () => {
  const fixture = createPeRvaFragments(0x1000, new Uint8Array(40), 20);
  assert.equal(resolveCoffTableReader(fixture.reader, fixture.mapping,
    0x1000, 0, 40, 0, 1)?.toFileOffset(0), fixture.mapping(0x1000));
  // The historical missing-LVA fallback skips the 32-byte IMAGE_COFF_SYMBOLS_HEADER.
  // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_coff_symbols_header
  assert.equal(resolveCoffTableReader(fixture.reader, fixture.mapping,
    0x1000, 0, 0, 0, 1)?.toFileOffset(0), fixture.mapping(0x1020));
  assert.equal(resolveCoffTableReader(fixture.reader, fixture.mapping,
    0x1000, 16, 0, 0, 1)?.offset, 48);
});
