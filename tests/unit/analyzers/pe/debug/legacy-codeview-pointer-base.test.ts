import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewPointerBase } from "../../../../../analyzers/pe/debug/legacy-codeview-pointer-base.js";
import { legacyReader, legacySymbol, legacyPascal } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewPointerBase, codeViewEntryThis } from "../../../../fixtures/pe-codeview-embedded-symbols.js";

for (const type of [2, 0x1002] as const) {
  void test(`CodeView pointer ${type} preserves its length-prefixed base type name`, async () => {
    const bytes = codeViewPointerBase(type, 8, [...new Array<number>(type === 2 ? 2 : 4).fill(0),
      ...legacyPascal("Base"), 0xf3, 0xf2, 0xf1]);

    assert.deepEqual(await readLegacyCodeViewPointerBase(legacyReader(bytes), type), { strings: ["Base"] });
  });

  for (const kind of [4, 5, 6, 7]) {
    void test(`CodeView pointer ${type}/${kind} preserves its complete base symbol`, async () => {
      const warnings: string[] = [];
      const bytes = codeViewPointerBase(type, kind, [...codeViewEntryThis(legacySymbol()), 0xf2, 0xf1]);

      assert.deepEqual(await readLegacyCodeViewPointerBase(legacyReader(bytes, warnings), type),
        { symbols: [{ type: 0xe, children: [{ type: 0x203, name: "public_name" }] }] });
      assert.deepEqual(warnings, []);
    });
  }

  for (const attributes of [0, 3, 9, 10, 11, 8 | 2 << 5, 8 | 3 << 5]) {
    void test(`CodeView pointer ${type}/${attributes} does not invent a name for other union variants`, async () => {
      const warnings: string[] = [];

      assert.deepEqual(await readLegacyCodeViewPointerBase(legacyReader(
        codeViewPointerBase(type, attributes, legacyPascal("not a name")), warnings), type), {});
      assert.deepEqual(warnings, []);
    });
  }

  void test(`CodeView pointer ${type} rejects incomplete fixed fields and base names`, async () => {
    await assert.rejects(readLegacyCodeViewPointerBase(legacyReader(new Uint8Array(4)), type), /bounds/);
    await assert.rejects(readLegacyCodeViewPointerBase(legacyReader(codeViewPointerBase(type, 8, [])), type), /bounds/);
    await assert.rejects(readLegacyCodeViewPointerBase(legacyReader(codeViewPointerBase(type, 3, [])), type), /bounds/);
    await assert.rejects(readLegacyCodeViewPointerBase(legacyReader(codeViewPointerBase(type, 2 << 5, [])), type), /bounds/);
  });

  for (const attributes of [13, 31, 8 | 5 << 5]) {
    void test(`CodeView pointer ${type}/${attributes} warns instead of decoding a reserved union variant`, async () => {
      const warnings: string[] = [];

      assert.deepEqual(await readLegacyCodeViewPointerBase(legacyReader(
        codeViewPointerBase(type, attributes, []), warnings), type), {});
      assert.deepEqual(warnings, ["CodeView pointer uses a reserved kind or mode; its base was not decoded."]);
    });
  }
}

void test("CodeView 64-bit pointer kind is reserved in the classic format and valid in wide types", async () => {
  const warnings: string[] = [];

  assert.deepEqual(await readLegacyCodeViewPointerBase(legacyReader(codeViewPointerBase(2, 12, []), warnings), 2), {});
  assert.equal(warnings.length, 1);
  assert.deepEqual(await readLegacyCodeViewPointerBase(legacyReader(
    codeViewPointerBase(0x1002, 12, []), warnings), 0x1002), {});
  assert.equal(warnings.length, 1);
});

void test("CodeView classic pointer records reject the later rvalue-reference mode", async () => {
  const warnings: string[] = [];

  assert.deepEqual(await readLegacyCodeViewPointerBase(legacyReader(
    codeViewPointerBase(2, 8 | 4 << 5, []), warnings), 2), {});
  assert.deepEqual(warnings, ["CodeView pointer uses a reserved kind or mode; its base was not decoded."]);
});

for (const [type, mode] of [[2, 1], [0x1002, 1], [0x1002, 4]] as const) {
  void test(`CodeView reference mode ${type}/${mode} retains its base name`, async () => {
    assert.deepEqual(await readLegacyCodeViewPointerBase(legacyReader(codeViewPointerBase(type,
      8 | mode << 5, [...new Array<number>(type === 2 ? 2 : 4).fill(0), ...legacyPascal("Base")])), type),
    { strings: ["Base"] });
  });
}
