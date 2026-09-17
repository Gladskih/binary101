import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfDynamicSymbols } from "../../../../analyzers/elf/dynamic-symbols.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

for (const offset of [-1n, 1024n, 1n << 60n]) {
  void test(`rejects dynamic symbol file offset ${offset}`, async () => {
    const fixture = relocationFixture();
    fixture.elf.sections[2]!.type = 11;
    fixture.elf.sections[2]!.offset = offset;
    const result = await parseElfDynamicSymbols({ ...fixture.elf, file: fixture.file() });
    assert.deepEqual(result?.exportSymbols, []);
    assert.match(result!.issues.join(" "), /outside the file/);
  });
}

void test("retains complete symbols from a truncated or partial table", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11;
  fixture.elf.sections[2]!.offset = 1000n;
  fixture.elf.sections[2]!.size = 25n;
  const result = await parseElfDynamicSymbols({ ...fixture.elf, file: fixture.file() });
  assert.equal(result?.total, 1);
  assert.match(result!.issues.join(" "), /truncated/);
  fixture.elf.sections[2]!.offset = 999n;
  const partial = await parseElfDynamicSymbols({ ...fixture.elf, file: fixture.file() });
  assert.equal(partial?.total, 1);
  assert.match(partial!.issues.join(" "), /aligned/);
});

for (const count of [1000000, 1000001]) {
  void test(`reports short reads in a dynamic table of ${count} entries`, async () => {
    const fixture = relocationFixture();
    fixture.elf.sections[2]!.type = 11;
    fixture.elf.sections[2]!.size = BigInt(count) * 24n; // Elf64_Sym, gABI 5.
    const file = new File([], "short-read");
    // Simulate a file becoming unreadable without allocating a million symbols.
    Object.defineProperty(file, "size", { value: 256 + count * 24 });
    const result = await parseElfDynamicSymbols({ ...fixture.elf, file });
    assert.equal(result?.total, count);
    assert.deepEqual(result?.exportSymbols, []);
    assert.match(result!.issues.join(" "), /symbol #0 is truncated/);
    assert.equal(result?.issues.some(issue => issue.includes("resource limit")), false);
  });
}

const largeDynamicSymbolTable = () => {
  const fixture = relocationFixture();
  // Former implementation cap + 1, not an ELF format limit.
  const count = 1000001;
  // Elf64_Sym: 24 bytes, st_info at +4, STT_SECTION=3 (gABI 5).
  // https://gabi.xinuos.com/elf/05-symtab.html
  const bytes = new Uint8Array(256 + count * 24 + 8);
  for (let index = 1; index < count; index += 1) bytes[256 + index * 24 + 4] = 3;
  bytes.set(fixture.bytes.subarray(280, 304), 256 + (count - 1) * 24);
  bytes[256 + (count - 1) * 24 + 4] = 0x12; // STB_GLOBAL | STT_FUNC.
  bytes.set(fixture.bytes.subarray(384, 392), bytes.length - 8);
  fixture.elf.sections[2]!.type = 11;
  fixture.elf.sections[2]!.size = BigInt(count * 24);
  fixture.elf.sections[3]!.offset = BigInt(bytes.length - 8);
  return { ...fixture.elf, file: new File([bytes], "large-dynsym") };
};

void test("reads dynamic symbols beyond the former one-million entry cap", async () => {
  const result = await parseElfDynamicSymbols(largeDynamicSymbolTable());

  assert.equal(result?.total, 1000001);
  assert.equal(result?.exportSymbols.length, 1);
  assert.equal(result?.exportSymbols[0]?.index, 1000000);
  assert.equal(result?.exportSymbols[0]?.name, "target");
  assert.deepEqual(result?.issues, []);
});
