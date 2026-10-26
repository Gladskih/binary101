import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewScopeSymbol } from "../../../../../analyzers/pe/debug/codeview-scope-symbols.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { localName, localRecord } from "../../../../fixtures/pe-codeview-locals.js";

void test("Inline sites preserve parent/end links, inlinee ID, invocation count and decoded annotations", async () => {
  const warnings: string[] = [];
  const record = localRecord(0x115d, [...[4, 80, 0x1004, 9].flatMap(legacyU32), 3, 5, 4, 12]);
  const result = await readCodeViewScopeSymbol(legacyReader(Uint8Array.from(record), warnings), 0x115d);

  assert.deepEqual(result, { scope: { kind: "inline", scopeOffsets: { parent: 4, end: 80 }, inlinee: 0x1004,
    invocations: 9, annotations: [{ opcode: 3, operands: [5] }, { opcode: 4, operands: [12] }] } });
  assert.deepEqual(warnings, []);
});

void test("UTF-8 adjustor thunks retain names, signed adjustment and variant target", async () => {
  const warnings: string[] = [];
  const record = localRecord(0x1102, [...[0, 96, 120, 32].flatMap(legacyU32), ...legacyU16(1),
    ...legacyU16(8), 1, ...localName("adjust"), ...legacyU16(0xfff8), ...localName("target")]);
  const result = await readCodeViewScopeSymbol(legacyReader(Uint8Array.from(record), warnings), 0x1102);

  assert.deepEqual(result, { name: "adjust", scope: { kind: "thunk", scopeOffsets: { parent: 0, end: 96, next: 120 },
    location: { segment: 1, offset: 32 }, codeLength: 8, ordinal: 1, adjustment: -8, target: "target" } });
  assert.deepEqual(warnings, []);
});

void test("WITH expressions preserve their names and lexical bounds", async () => {
  const warnings: string[] = [];
  const record = localRecord(0x1104, [...[4, 96, 16, 32].flatMap(legacyU32), ...legacyU16(1), ...localName("object.member")]);
  const result = await readCodeViewScopeSymbol(legacyReader(Uint8Array.from(record), warnings), 0x1104);

  assert.deepEqual(result, { name: "object.member", scope: { kind: "with", scopeOffsets: { parent: 4, end: 96 },
    location: { segment: 1, offset: 32 }, codeLength: 16 } });
  assert.deepEqual(warnings, []);
});

for (const type of [0x106, 0x206]) {
  const address = type === 0x106 ? legacyU16(32) : legacyU32(32);
  void test(`Legacy thunk ${type} retains counted names and virtual table entry`, async () => {
    const warnings: string[] = [];
    const record = localRecord(type, [...[0, 96, 120].flatMap(legacyU32), ...address, ...legacyU16(1),
      ...legacyU16(8), 2, 5, ...new TextEncoder().encode("vcall"), ...legacyU16(0xfffe)]);

    assert.deepEqual(await readCodeViewScopeSymbol(legacyReader(Uint8Array.from(record), warnings), type),
      { name: "vcall", scope: { kind: "thunk", scopeOffsets: { parent: 0, end: 96, next: 120 },
        location: { segment: 1, offset: 32 }, codeLength: 8, ordinal: 2, virtualEntry: -2 } });
    assert.deepEqual(warnings, []);
  });
}

for (const type of [0x107, 0x108, 0x208]) {
  const addresses = type === 0x208 ? [...legacyU32(16), ...legacyU32(32)] : [...legacyU16(16), ...legacyU16(32)];
  const kind = type === 0x107 ? "block" : "with";
  void test(`Legacy lexical scope ${type} preserves 16/32-bit fields`, async () => {
    const warnings: string[] = [];
    const record = localRecord(type, [...[4, 96].flatMap(legacyU32), ...addresses, ...legacyU16(1), 3, 111, 98, 106]);

    assert.deepEqual(await readCodeViewScopeSymbol(legacyReader(Uint8Array.from(record), warnings), type),
      { name: "obj", scope: { kind, scopeOffsets: { parent: 4, end: 96 },
        location: { segment: 1, offset: 32 }, codeLength: 16 } });
    assert.deepEqual(warnings, []);
  });
}

for (const type of [0x114d, 0x115d, 0x106, 0x1102, 0x108]) {
  void test(`Truncated scope ${type} keeps its kind and produces a warning`, async () => {
    const warnings: string[] = [];
    const result = await readCodeViewScopeSymbol(legacyReader(Uint8Array.from(localRecord(type, [])), warnings), type);

    assert.ok(result?.scope.kind);
    assert.equal(result.scope.scopeOffsets, undefined);
    assert.match(warnings.join(" | "), /bounds/);
  });
}

void test("Truncated thunk variant retains the valid fixed fields and name", async () => {
  const warnings: string[] = [];
  const record = localRecord(0x1102, [...[0, 96, 0, 32].flatMap(legacyU32), ...legacyU16(1), ...legacyU16(8),
    1, ...localName("adjust"), 255]);
  const result = await readCodeViewScopeSymbol(legacyReader(Uint8Array.from(record), warnings), 0x1102);

  assert.equal(result?.name, "adjust");
  assert.equal(result?.scope.ordinal, 1);
  assert.match(warnings.join(" | "), /bounds/);
});

for (const ordinal of [0, 3, 7]) {
  void test(`Thunk ordinal ${ordinal} preserves known or unknown variant identity`, async () => {
    const warnings: string[] = [];
    const record = localRecord(0x1102, [...[0, 96, 0, 32].flatMap(legacyU32), ...legacyU16(1), ...legacyU16(8),
      ordinal, ...localName("thunk"), 0]);
    const result = await readCodeViewScopeSymbol(legacyReader(Uint8Array.from(record), warnings), 0x1102);

    assert.equal(result?.scope.ordinal, ordinal);
    assert.equal(warnings.length, ordinal === 0 ? 0 : 1);
  });
}

void test("Non-scope records are left for other decoders", async () => {
  assert.equal(await readCodeViewScopeSymbol(legacyReader(new Uint8Array(), []), 0x113e), null);
});
