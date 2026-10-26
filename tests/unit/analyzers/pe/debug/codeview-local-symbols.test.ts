import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewLocal } from "../../../../../analyzers/pe/debug/codeview-local-symbols.js";
import { legacyReader, legacyU16, legacyU32, legacyPascal } from "../../../../fixtures/pe-legacy-codeview.js";
import { localRecord, localName, localVariableRecord } from "../../../../fixtures/pe-codeview-locals.js";

// Layout bytes independently transcribed from cvinfo.h's 16-bit/ST/SZ structs.
for (const [type, body, location] of [
  [2, [...legacyU16(0x1234), ...legacyU16(22), ...legacyPascal("name")], { kind: "register", register: 22 }],
  [0x1001, [...legacyU32(0x1234), ...legacyU16(22), ...legacyPascal("name")], { kind: "register", register: 22 }],
  [0x1106, [...legacyU32(0x1234), ...legacyU16(334), ...localName("name")], { kind: "register", register: 334 }],
  [0x100, [...legacyU16(0xfff8), ...legacyU16(0x1234), ...legacyPascal("name")], { kind: "frameRelative", offset: -8 }],
  [0x200, [...legacyU32(0xfffffff8), ...legacyU16(0x1234), ...legacyPascal("name")], { kind: "frameRelative", offset: -8 }],
  [0x1006, [...legacyU32(0xfffffff8), ...legacyU32(0x1234), ...legacyPascal("name")], { kind: "frameRelative", offset: -8 }],
  [0x110b, [...legacyU32(0xfffffff8), ...legacyU32(0x1234), ...localName("name")], { kind: "frameRelative", offset: -8 }],
  [0x10c, [...legacyU16(0xfff8), ...legacyU16(22), ...legacyU16(0x1234), ...legacyPascal("name")],
    { kind: "registerOffset", offset: 65528, register: 22 }],
  [0x20c, [...legacyU32(0xfffffff8), ...legacyU16(22), ...legacyU16(0x1234), ...legacyPascal("name")],
    { kind: "registerOffset", offset: 4294967288, register: 22 }],
  [0x100d, [...legacyU32(0xfffffff8), ...legacyU32(0x1234), ...legacyU16(22), ...legacyPascal("name")],
    { kind: "registerOffset", offset: 4294967288, register: 22 }],
  [0x1111, [...legacyU32(0xfffffff8), ...legacyU32(0x1234), ...legacyU16(334), ...localName("name")],
    { kind: "registerOffset", offset: 4294967288, register: 334 }]
] as const) {
  void test(`CodeView local layout ${type} preserves its type and the declared offset signedness`, async () => {
    const warnings: string[] = [];
    const parsed = await readCodeViewLocal(legacyReader(localRecord(type, body), warnings), type);

    assert.deepEqual(parsed, { name: "name", local: { typeIndex: 0x1234, location } });
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView optimized local and file-static names retain flags and module string references", async () => {
  assert.deepEqual(await readCodeViewLocal(legacyReader(localVariableRecord("<local>&amp;", 0x7ff)), 0x113e),
    { name: "<local>&amp;", local: { typeIndex: 0x1001, flags: 0x7ff } });
  const bytes = localRecord(0x1153, [...legacyU32(0xffffffff), ...legacyU32(0x12345678), ...legacyU16(0), 0]);
  assert.deepEqual(await readCodeViewLocal(legacyReader(bytes), 0x1153),
    { name: "", local: { typeIndex: 0xffffffff, moduleOffset: 0x12345678, flags: 0 } });
  assert.equal(await readCodeViewLocal(legacyReader([]), 0x113d), null);
});

void test("CodeView local fields survive a malformed name and unknown flags", async () => {
  const warnings: string[] = [];
  const bytes = localVariableRecord("name", 0x8000).slice(0, 10);
  const result = await readCodeViewLocal(legacyReader(bytes, warnings), 0x113e);

  assert.deepEqual(result, { local: { typeIndex: 0x1001, flags: 0x8000 } });
  assert.match(warnings.join(" | "), /reserved bits/);
  assert.match(warnings.join(" | "), /local name/);
  await assert.rejects(readCodeViewLocal(legacyReader(bytes.slice(0, 9)), 0x113e), /bounds/);
});
