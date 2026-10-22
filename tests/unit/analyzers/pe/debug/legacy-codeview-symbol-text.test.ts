import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewSymbolText } from "../../../../../analyzers/pe/debug/legacy-codeview-symbol-text.js";
import { legacyReader, legacySymbol } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewTextRecord, codeViewUtf8 } from "../../../../fixtures/pe-codeview-type-strings.js";
import { codeViewAnnotations, codeViewUtf16 } from "../../../../fixtures/pe-codeview-symbol-strings.js";

void test("CodeView annotations retain counted UTF-8 strings including empty strings and exclude padding", async () => {
  const warnings: string[] = [];
  const result = await readLegacyCodeViewSymbolText(legacyReader(codeViewAnnotations([
    ...codeViewUtf8("first"), 0, ...codeViewUtf8("имя"), ...codeViewUtf8("padding")], 3), warnings), 0x1019);

  assert.deepEqual(result, { strings: ["first", "", "имя"] });
  assert.deepEqual(warnings, []);
});

void test("CodeView empty annotations do not require a string payload", async () => {
  const warnings: string[] = [];

  assert.deepEqual(await readLegacyCodeViewSymbolText(legacyReader(codeViewAnnotations([], 0), warnings), 0x1019),
    { strings: [] });
  assert.deepEqual(warnings, []);
});

for (const [count, tail] of [[3, []], [65535, []], [2, [0xff, 0]], [2, [65]]] as const) {
  void test(`CodeView annotation prefix survives malformed later strings ${count}/${tail}`, async () => {
    const warnings: string[] = [];
    const result = await readLegacyCodeViewSymbolText(legacyReader(codeViewAnnotations([
      ...codeViewUtf8("kept"), ...tail], count), warnings), 0x1019);

    assert.deepEqual(result, { strings: ["kept"] });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /^CodeView symbol string:/);
  });
}

for (const flags of [0, 1]) {
  void test(`CodeView environment strings with flags ${flags} retain ordered fields and stop before padding`, async () => {
    const warnings: string[] = [];
    const bytes = codeViewTextRecord(0x113d, 5, [...codeViewUtf8("cwd"), ...codeViewUtf8("путь"), 0, 0xff]);
    bytes[4] = flags;
    const result = await readLegacyCodeViewSymbolText(legacyReader(bytes, warnings), 0x113d);

    assert.deepEqual(result, { strings: ["cwd", "путь"] });
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView environment fields accept an empty terminated block", async () => {
  const warnings: string[] = [];

  assert.deepEqual(await readLegacyCodeViewSymbolText(legacyReader(codeViewTextRecord(0x113d, 5, [0]), warnings),
    0x113d), { strings: [] });
  assert.deepEqual(warnings, []);
});

for (const type of [0x1013, 0x1116, 0x113d]) {
  void test(`CodeView command block ${type} preserves empty values and subsequent pairs`, async () => {
    const warnings: string[] = [];
    // C7Compile2/C7Envblock stop at an empty key, not at an empty value.
    // microsoft-pdb/cvdump/dumpsym7.cpp at 805655a28bd8198004be2ac27e6e0290121a5e89.
    const fields = [...codeViewUtf8("empty"), 0, ...codeViewUtf8("next"), ...codeViewUtf8("kept"), 0, 0xff];
    const bytes = type === 0x113d ? codeViewTextRecord(type, 5, fields)
      : [...legacySymbol(type, "compiler", 22), ...fields];
    const result = await readLegacyCodeViewSymbolText(legacyReader(bytes, warnings), type);

    assert.deepEqual(result.strings, ["empty", "", "next", "kept"]);
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView environment flags diagnose reserved bits without discarding readable fields", async () => {
  const warnings: string[] = [];
  const bytes = codeViewTextRecord(0x113d, 5, [...codeViewUtf8("cwd"), ...codeViewUtf8("workspace"), 0]);
  bytes[4] = 0xfe;
  const result = await readLegacyCodeViewSymbolText(legacyReader(bytes, warnings), 0x113d);

  assert.deepEqual(result, { strings: ["cwd", "workspace"] });
  assert.deepEqual(warnings, ["CodeView environment flags set reserved bits."]);
});

for (const bytes of [[], codeViewUtf8("cwd")]) {
  void test(`CodeView unterminated environment block preserves complete strings: ${bytes.length}`, async () => {
    const warnings: string[] = [];
    const result = await readLegacyCodeViewSymbolText(
      legacyReader(codeViewTextRecord(0x113d, 5, bytes), warnings), 0x113d);

    assert.deepEqual(result, { strings: bytes.length ? ["cwd"] : [] });
    assert.deepEqual(warnings, ["CodeView symbol string block has no final empty-string terminator."]);
  });
}

for (const tail of [[65], [0xff, 0]]) {
  void test(`CodeView damaged environment text retains preceding strings: ${tail}`, async () => {
    const warnings: string[] = [];
    const result = await readLegacyCodeViewSymbolText(legacyReader(codeViewTextRecord(0x113d, 5,
      [...codeViewUtf8("cwd"), ...tail]), warnings), 0x113d);

    assert.deepEqual(result, { strings: ["cwd"] });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /^CodeView symbol string:/);
  });
}

for (const type of [0x1013, 0x1116]) {
  void test(`CodeView compiler ${type} retains its version and optional text as separate values`, async () => {
    const warnings: string[] = [];
    const result = await readLegacyCodeViewSymbolText(legacyReader([
      ...legacySymbol(type, "compiler", 22), ...codeViewUtf8("cwd"), ...codeViewUtf8("workspace"), 0], warnings), type);

    assert.deepEqual(result, { name: "compiler", strings: ["cwd", "workspace"] });
    assert.deepEqual(warnings, []);
  });

  void test(`CodeView compiler ${type} can omit the optional text block`, async () => {
    const warnings: string[] = [];

    assert.deepEqual(await readLegacyCodeViewSymbolText(legacyReader(legacySymbol(type, "compiler", 22), warnings), type),
      { name: "compiler" });
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView ST compiler options use unspecified ANSI with a visible code-page warning", async () => {
  const warnings: string[] = [];
  const result = await readLegacyCodeViewSymbolText(legacyReader([
    ...legacySymbol(0x1013, "compiler", 22), 0xe9, 0, 0xe9, 0, 0], warnings), 0x1013);

  assert.deepEqual(result, { name: "compiler", strings: ["é", "é"] });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /Windows-1252/);
});

void test("CodeView SZ compiler text preserves Unicode and a readable version when extra data is malformed", async () => {
  const warnings: string[] = [];
  const result = await readLegacyCodeViewSymbolText(legacyReader([
    ...legacySymbol(0x1116, "компилятор", 22), ...codeViewUtf8("аргумент"), 0xff, 0], warnings), 0x1116);

  assert.deepEqual(result, { name: "компилятор", strings: ["аргумент"] });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /^CodeView symbol string:/);
});

void test("CodeView PDB maps retain both UTF-16 paths and exclude record padding", async () => {
  const warnings: string[] = [];
  const result = await readLegacyCodeViewSymbolText(legacyReader(codeViewTextRecord(0x1161, 4, [
    ...codeViewUtf16("исходный.pdb"), ...codeViewUtf16("target.pdb"), 0xff]), warnings), 0x1161);

  assert.deepEqual(result, { strings: ["исходный.pdb", "target.pdb"] });
  assert.deepEqual(warnings, []);
});

for (const tail of [[], [65, 0], [0, 0xd8, 0, 0]]) {
  void test(`CodeView PDB maps retain the source when the target is truncated or malformed: ${tail}`, async () => {
    const warnings: string[] = [];
    const result = await readLegacyCodeViewSymbolText(legacyReader(codeViewTextRecord(0x1161, 4, [
      ...codeViewUtf16("source.pdb"), ...tail]), warnings), 0x1161);

    assert.deepEqual(result, { strings: ["source.pdb"] });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /^CodeView symbol string:/);
  });
}

void test("CodeView ordinary symbol names and unnamed record kinds keep their existing contract", async () => {
  assert.deepEqual(await readLegacyCodeViewSymbolText(legacyReader(legacySymbol()), 0x203), { name: "public_name" });
  assert.deepEqual(await readLegacyCodeViewSymbolText(legacyReader([]), 6), {});
  await assert.rejects(readLegacyCodeViewSymbolText(legacyReader([]), 0x110e), /terminated/);
});

for (const type of [0x1013, 0x1116, 0x1019, 0x113d]) {
  void test(`CodeView symbol text ${type} rejects missing mandatory fields`, async () => {
    await assert.rejects(readLegacyCodeViewSymbolText(legacyReader(new Uint8Array(4)), type), /bounds/);
  });
}
