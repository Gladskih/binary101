import assert from "node:assert/strict";
import { test } from "node:test";
import { readTd32SymbolMetadata } from "../../../../../analyzers/pe/debug/td32-symbol-metadata.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { localRecord } from "../../../../fixtures/pe-codeview-locals.js";

void test("TD32 procedures retain the common JCL/map2dbg fields without choosing an ambiguous type-index layout", async () => {
  const warnings: string[] = [];
  const bytes = localRecord(0x205, [...[0, 128, 0, 64, 8, 56, 32].flatMap(legacyU32),
    ...legacyU16(1), ...legacyU16(0), ...legacyU32(0x1008), ...legacyU32(7), ...legacyU32(0)]);

  assert.deepEqual(await readTd32SymbolMetadata(legacyReader(Uint8Array.from(bytes), warnings), 0x205),
    { nameIndex: 7, metadata: { location: { offset: 32, segment: 1 }, codeLength: 64,
      debugRange: { start: 8, end: 56 }, scopeOffsets: { parent: 0, end: 128, next: 0 } } });
  assert.deepEqual(warnings, []);
});

void test("TD32 data, register and BP-relative variables preserve stored fields and signedness", async () => {
  const data = localRecord(0x202, [...legacyU32(0xf1234567), ...legacyU16(3), ...legacyU16(1),
    ...legacyU32(0x1008), ...legacyU32(7)]);
  const stack = localRecord(0x200, [...legacyU32(0xfffffff8), ...legacyU32(0x1008), ...legacyU32(8)]);
  const register = localRecord(2, [...legacyU32(0x1008), ...legacyU16(17), ...legacyU32(9)]);

  assert.deepEqual(await readTd32SymbolMetadata(legacyReader(Uint8Array.from(data)), 0x202),
    { nameIndex: 7, metadata: { location: { offset: 0xf1234567, segment: 3 }, flags: 1, typeIndex: 0x1008 } });
  assert.deepEqual(await readTd32SymbolMetadata(legacyReader(Uint8Array.from(stack)), 0x200),
    { nameIndex: 8, metadata: { frameOffset: -8, typeIndex: 0x1008 } });
  assert.deepEqual(await readTd32SymbolMetadata(legacyReader(Uint8Array.from(register)), 2),
    { nameIndex: 9, metadata: { typeIndex: 0x1008, register: 17 } });
});

void test("TD32 symbol references retain names and addresses previously lost to the inventory", async () => {
  const bytes = localRecord(0x20, [...[0, 0x1008, 7, 0, 64].flatMap(legacyU32), ...legacyU16(2), ...legacyU32(0)]);

  assert.deepEqual(await readTd32SymbolMetadata(legacyReader(Uint8Array.from(bytes)), 0x20),
    { nameIndex: 7, metadata: { typeIndex: 0x1008, location: { offset: 64, segment: 2 } } });
});

for (const [type, body, expected] of [
  [3, [...legacyU32(0x1008), ...legacyU32(7)], { nameIndex: 7, metadata: { typeIndex: 0x1008 } }],
  [4, [...legacyU32(0x1008), ...legacyU16(3), ...legacyU32(7)],
    { nameIndex: 7, metadata: { typeIndex: 0x1008, flags: 3 } }],
  [0x207, [...[4, 96, 16, 32].flatMap(legacyU32), ...legacyU16(1), ...legacyU32(7)],
    { nameIndex: 7, metadata: { scopeOffsets: { parent: 4, end: 96 }, codeLength: 16,
      location: { offset: 32, segment: 1 } } }],
  [0x210, [...legacyU32(32), ...legacyU16(1)], { metadata: { location: { offset: 32, segment: 1 } } }],
  [0x211, [...legacyU16(0), ...legacyU32(32), ...legacyU32(16), ...legacyU16(17)],
    { metadata: { rangeStart: 32, codeLength: 16, register: 17 } }],
  [0x212, [...legacyU32(32), ...legacyU16(16)], { metadata: { rangeStart: 32, codeLength: 16 } }],
  [0x213, legacyU16(7), { metadata: { flags: 7 } }],
  [0x25, [...legacyU32(7), ...legacyU32(0), ...legacyU16(2)], { nameIndex: 7, metadata: { usingCount: 2 } }],
  [0x27, [...legacyU32(0x1008), ...legacyU16(3), ...legacyU32(7), ...legacyU32(0), ...legacyU32(0xffffffff)],
    { nameIndex: 7, metadata: { typeIndex: 0x1008, flags: 3, value: "-1" } }],
  [0x24, [...legacyU32(1), ...legacyU32(2)], { metadata: { nameIndices: [1, 2] } }],
  [0x26, [...legacyU16(2), ...legacyU32(1), ...legacyU32(2)], { metadata: { nameIndices: [1, 2] } }]
] as const) {
  void test(`TD32 symbol ${type} keeps its confirmed fixed fields`, async () => {
    const warnings: string[] = [];

    assert.deepEqual(await readTd32SymbolMetadata(
      legacyReader(Uint8Array.from(localRecord(type, body)), warnings), type), expected);
    assert.deepEqual(warnings, []);
  });
}

void test("TD32 invalid spans and arithmetic overflow warn without discarding the stored fields", async () => {
  const warnings: string[] = [];
  const bytes = localRecord(0x205, [...[0, 128, 0, 64, 60, 65, 0xfffffff0].flatMap(legacyU32),
    ...legacyU16(1), ...legacyU16(0), ...legacyU32(0), ...legacyU32(7)]);

  assert.equal((await readTd32SymbolMetadata(
    legacyReader(Uint8Array.from(bytes), warnings), 0x205))?.metadata?.codeLength, 64);
  assert.match(warnings.join(" | "), /debug span/);
  assert.match(warnings.join(" | "), /32-bit stored/);
});

void test("TD32 labels preserve common fields while refusing the conflicting name-index layouts", async () => {
  const warnings: string[] = [];
  const bytes = localRecord(0x209, [...legacyU32(32), ...legacyU16(1), 4, ...legacyU32(7)]);

  assert.deepEqual(await readTd32SymbolMetadata(legacyReader(Uint8Array.from(bytes), warnings), 0x209),
    { metadata: { location: { offset: 32, segment: 1 }, flags: 4 } });
  assert.match(warnings.join(" | "), /name layouts differ/);
});

for (const type of [2, 0x200, 0x205, 0x20, 0x207, 0x210, 0x211, 0x212, 0x213, 0x25, 0x26, 0x27, 0x206]) {
  void test(`TD32 symbol ${type} contains its truncation warning`, async () => {
    const warnings: string[] = [];

    assert.equal(await readTd32SymbolMetadata(
      legacyReader(Uint8Array.from(localRecord(type, [])), warnings), type), undefined);
    assert.match(warnings.join(" | "), /bounds/);
  });
}

void test("TD32 truncated and trailing import arrays never read outside their own symbol", async () => {
  const warnings: string[] = [];
  const partial = localRecord(0x24, [...legacyU32(7), 1]);

  assert.deepEqual(await readTd32SymbolMetadata(legacyReader(Uint8Array.from(partial), warnings), 0x24),
    { metadata: { nameIndices: [7] } });
  assert.match(warnings.join(" | "), /trailing bytes/);
  assert.equal(await readTd32SymbolMetadata(legacyReader(new Uint8Array(), warnings), 0x7777), undefined);
});

void test("TD32 adjustor thunks retain their packed names and signed 32-bit delta", async () => {
  const warnings: string[] = [];
  const bytes = localRecord(0x206, [...[0, 128, 0, 32].flatMap(legacyU32), ...legacyU16(1),
    ...legacyU16(8), 1, ...legacyU32(7), ...legacyU32(0xfffffff8), ...legacyU32(9)]);

  assert.deepEqual(await readTd32SymbolMetadata(legacyReader(Uint8Array.from(bytes), warnings), 0x206),
    { nameIndex: 7, metadata: { scopeOffsets: { parent: 0, end: 128, next: 0 },
      location: { offset: 32, segment: 1 }, codeLength: 8, ordinal: 1, adjustment: -8, targetNameIndex: 9 } });
  assert.deepEqual(warnings, []);
});

for (const ordinal of [0, 1, 3]) {
  void test(`TD32 thunk ordinal ${ordinal} retains its fixed prefix when its variant is unavailable`, async () => {
    const warnings: string[] = [];
    const bytes = localRecord(0x206, [...[0, 128, 0, 32].flatMap(legacyU32),
      ...legacyU16(1), ...legacyU16(8), ordinal, ...legacyU32(7)]);
    const result = await readTd32SymbolMetadata(legacyReader(Uint8Array.from(bytes), warnings), 0x206);

    assert.equal(result?.nameIndex, 7);
    assert.equal(result?.metadata?.ordinal, ordinal);
    assert.equal(warnings.length, ordinal === 0 ? 0 : 1);
  });
}

for (const [start, end, offset, warningCount] of [[20, 10, 32, 1], [64, 64, 32, 0], [0, 64, 0xffffffc0, 0]]) {
  void test(`TD32 debug/range boundaries ${start}:${end} at ${offset} distinguish strict limits`, async () => {
    const warnings: string[] = [];
    const bytes = localRecord(0x205, [...[0, 128, 0, 64, start!, end!, offset!].flatMap(legacyU32),
      ...legacyU16(1), ...legacyU16(0), ...legacyU32(0), ...legacyU32(7)]);

    assert.equal((await readTd32SymbolMetadata(legacyReader(Uint8Array.from(bytes), warnings), 0x205))?.nameIndex, 7);
    assert.equal(warnings.length, warningCount);
  });
}
