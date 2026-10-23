import assert from "node:assert/strict";
import { test } from "node:test";
import { LegacyCodeViewReader } from "../../../../../analyzers/pe/debug/legacy-codeview-reader.js";
import { legacyReader } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewUtf16 } from "../../../../fixtures/pe-codeview-symbol-strings.js";

void test("CodeView fixed-length ANSI values preserve long literals with shared code-page diagnostics", async () => {
  const warnings: string[] = [];
  const reader = legacyReader([...new Array<number>(300).fill(65), 0xe9], warnings);
  assert.equal(await reader.ansiBytes(0, 301), "A".repeat(300) + "é");
  assert.equal(await reader.ansiBytes(300, 1), "é");
  assert.equal(warnings.length, 1);
  await assert.rejects(reader.ansiBytes(300, 2), /bounds/);
});

void test("CodeView UTF-16 PDB paths stream surrogate pairs across read boundaries", async () => {
  const text = "x".repeat(127) + "😀" + "путь";
  const bytes = codeViewUtf16(text);

  assert.deepEqual(await legacyReader(bytes).utf16Name(0), { name: text, end: bytes.length });
  assert.deepEqual(await legacyReader([0, 0]).utf16Name(0), { name: "", end: 2 });
  assert.deepEqual(await legacyReader([0xff, 0xfe, 65, 0, 0, 0]).utf16Name(0), { name: "\ufeffA", end: 6 });
});

for (const bytes of [[], [65], [65, 0], [65, 0, 0]]) {
  void test(`CodeView UTF-16 PDB paths require a complete two-byte terminator: ${bytes.length}`, async () => {
    await assert.rejects(legacyReader(bytes).utf16Name(0), /UTF-16.*NUL-terminated/);
  });
}

for (const bytes of [[0, 0xd8, 0, 0], [0, 0xdc, 0, 0]]) {
  void test(`CodeView UTF-16 PDB paths reject unpaired surrogates: ${bytes}`, async () => {
    await assert.rejects(legacyReader(bytes).utf16Name(0), /encoded data/);
  });
}

const subject = (bytes: number[]) => {
  const data = Uint8Array.from(bytes);
  const warnings: string[] = [];
  const reader = new LegacyCodeViewReader(data.length, async (offset, size) =>
    new DataView(data.slice(offset, offset + size).buffer), warning => warnings.push(warning));
  return { reader, warnings };
};

void test("legacy CodeView reader refuses ranges outside its subsection", async () => {
  const { reader } = subject([1, 2]);

  assert.equal((await reader.view(0, 2)).getUint16(0, true), 513);
  await assert.rejects(reader.view(1, 2), /bounds/);
  await assert.rejects(reader.view(-1, 1), /bounds/);
  await assert.rejects(reader.view(0, Number.MAX_SAFE_INTEGER), /bounds/);
  await assert.rejects(reader.view(0.5, 1), /bounds/);
  await assert.rejects(reader.view(0, -1), /bounds/);
  await assert.rejects(reader.view(0, 0.5), /bounds/);
});

void test("legacy CodeView reader detects actual short reads and scopes nested ranges", async () => {
  const short = new LegacyCodeViewReader(4, async () => new DataView(new ArrayBuffer(1)), () => {});
  const reader = legacyReader([1, 2, 3, 4, 5]);

  await assert.rejects(short.uint32(0), /truncated/);
  assert.equal(await reader.uint16(0), 513);
  assert.equal(await reader.uint32(0), 0x04030201);
  assert.equal(await reader.subsection(1, 3).uint16(1), 1027);
  await assert.rejects(reader.subsection(4, 2).view(0, 2), /bounds/);
});

void test("legacy counted ANSI names preserve empty strings and share one code-page warning", async () => {
  const warnings: string[] = [];
  const reader = legacyReader([0, 2, 65, 0x80, 1, 0x80], warnings);

  assert.deepEqual(await reader.pascal(0), { name: "", end: 1 });
  assert.deepEqual(await reader.pascal(1), { name: "A€", end: 4 });
  assert.equal((await reader.subsection(4, 2).pascal(0)).name, "€");
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /Windows-1252/);
  await assert.rejects(reader.pascal(5), /bounds/);
});

void test("legacy terminated strings stream through windows and require a terminator", async () => {
  const text = "x".repeat(255) + "😀";
  const utf8 = legacyReader([...new TextEncoder().encode(text), 0]);
  const ansi = legacyReader([...new Array<number>(256).fill(65), 0x80, 0]);

  assert.equal(await utf8.utf8(0), text);
  assert.deepEqual(await utf8.utf8Name(0), { name: text, end: 260 });
  assert.deepEqual(await ansi.ansi(0), { name: "A".repeat(256) + "€", end: 258 });
  assert.deepEqual(await legacyReader([0]).ansi(0), { name: "", end: 1 });
  assert.equal(await legacyReader([0]).utf8(0), "");
  assert.equal(await legacyReader([0xef, 0xbb, 0xbf, 65, 0]).utf8(0), "\ufeffA");
  await assert.rejects(legacyReader([65]).utf8(0), /NUL-terminated/);
  await assert.rejects(legacyReader([65]).ansi(0), /NUL-terminated/);
  await assert.rejects(legacyReader([0xff, 0]).utf8(0), /encoded data/);
});
