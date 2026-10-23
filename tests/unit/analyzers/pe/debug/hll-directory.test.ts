import assert from "node:assert/strict";
import { test } from "node:test";
import { readHllDirectory, readHllModule } from "../../../../../analyzers/pe/debug/hll-directory.js";
import { createHll, hllModule } from "../../../../fixtures/pe-hll.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("HLL directory uses DWORD sizes and accepts explicitly sized header and entries", async () => {
  const bytes = Uint8Array.from([...new Array<number>(8).fill(0),
    ...legacyU16(12), ...legacyU16(16), ...legacyU32(1),
    ...legacyU32(0), ...legacyU16(0x103), ...legacyU16(5),
    ...legacyU32(0x12345678), ...legacyU32(0x87654321), ...legacyU32(0)]);
  assert.deepEqual(await readHllDirectory(legacyReader(bytes), 8),
    { flags: 0, entries: [{ type: 0x103, module: 5, offset: 0x12345678, size: 0x87654321 }] });
});

void test("HLL module contributions use ten bytes and preserve version and unknown style literally", async () => {
  const bytes = Uint8Array.from([...hllModule("??", 0x600), ...legacyU16(2), ...legacyU32(0x10000), ...legacyU32(0x20000)]);
  bytes.set(legacyU16(2), 14);
  bytes.set(legacyU16(3), 10);
  bytes.set(legacyU16(4), 12);
  const data = await readHllModule(legacyReader(bytes));
  assert.deepEqual(data, { kind: "module", name: "hll.obj", overlay: 3, library: 4, style: "??", version: 0x600,
    segments: [{ segment: 1, offset: 16, size: 32 }, { segment: 2, offset: 0x10000, size: 0x20000 }] });
  await assert.rejects(readHllModule(legacyReader(bytes.slice(0, -1))), /segments are truncated/);
});

void test("HLL malformed directory sizes and offsets fail at bounded reads", async () => {
  await assert.rejects(readHllDirectory(legacyReader(createHll([])), 0), /overlaps/);
  await assert.rejects(readHllDirectory(legacyReader([]), 8), /bounds/);
  const bytes = createHll([]);
  bytes.set(legacyU16(11), 10);
  await assert.rejects(readHllDirectory(legacyReader(bytes), 8), /entry size/);
});

void test("HLL directory preserves complete entries before a truncated last entry", async () => {
  const warnings: string[] = [];
  const bytes = Uint8Array.from([...new Array<number>(8).fill(0), ...legacyU16(8), ...legacyU16(12), ...legacyU32(2),
    ...legacyU16(0x103), ...legacyU16(1), ...legacyU32(32), ...legacyU32(0xffffffff), ...new Array<number>(7).fill(0)]);
  const directory = await readHllDirectory(legacyReader(bytes, warnings), 8);
  assert.deepEqual(directory.entries, [{ type: 0x103, module: 1, offset: 32, size: 0xffffffff }]);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /past payload bounds/);
});

void test("HLL modules walk every additional ten-byte contribution after the module name", async () => {
  const bytes = Uint8Array.from([...hllModule(), ...legacyU16(2), ...legacyU32(40), ...legacyU32(50),
    ...legacyU16(3), ...legacyU32(60), ...legacyU32(70)]);
  bytes.set(legacyU16(3), 14);
  const module = await readHllModule(legacyReader(bytes));
  assert.deepEqual(module.segments, [{ segment: 1, offset: 16, size: 32 },
    { segment: 2, offset: 40, size: 50 }, { segment: 3, offset: 60, size: 70 }]);
});
