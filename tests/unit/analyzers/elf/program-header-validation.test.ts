import assert from "node:assert/strict";
import { test } from "node:test";
import { validateElfProgramHeaders } from
  "../../../../analyzers/elf/program-header-validation.js";
import type { ElfProgramHeader } from "../../../../analyzers/elf/types.js";

// gABI 7: PT_LOAD=1, PT_INTERP=3, PT_PHDR=6; offsets here are synthetic.
// https://gabi.xinuos.com/elf/07-pheader.html
const segment = (fields: Partial<ElfProgramHeader> = {}): ElfProgramHeader => ({
  index: 0, type: 1, typeName: null, offset: 0n, vaddr: 0x1000n, paddr: 0n,
  filesz: 64n, memsz: 128n, flags: 4, flagNames: [], align: 0x1000n, ...fields
});

for (const fields of [
  {}, { align: 0n }, { align: 1n }, { filesz: 128n },
  { filesz: 0n, offset: 4096n }, { type: 0, offset: 4096n, filesz: 4096n },
  { offset: 16n, vaddr: 0x1010n, align: 16n }
]) {
  void test(`accepts valid segment ${JSON.stringify(fields, (_, value: unknown) =>
    typeof value === "bigint" ? value.toString() : value)}`, () => {
    const issues: string[] = [];

    validateElfProgramHeaders([segment(fields)], 128, issues);

    assert.deepEqual(issues, []);
  });
}

for (const [fields, diagnostic] of [
  [{ filesz: 129n, memsz: 128n }, /p_filesz.*p_memsz/],
  [{ align: 3n }, /p_align.*power of two/],
  [{ offset: 1n }, /p_vaddr.*p_offset/],
  [{ offset: 128n, filesz: 1n, align: 1n }, /outside the file/],
  [{ offset: 1n << 63n, align: 1n }, /outside the file/]
] as const) {
  void test(`reports malformed segment: ${diagnostic}`, () => {
    const issues: string[] = [];

    validateElfProgramHeaders([segment(fields)], 128, issues);

    assert.match(issues.join(" "), diagnostic);
  });
}

void test("reports descending PT_LOAD addresses across intervening segments", () => {
  const issues: string[] = [];

  validateElfProgramHeaders([segment(), segment({ index: 1, type: 4 }),
    segment({ index: 2, vaddr: 0n })], 128, issues);

  assert.match(issues.join(" "), /ascending.*p_vaddr/);
});

void test("accepts equal and ascending PT_LOAD addresses", () => {
  const issues: string[] = [];

  validateElfProgramHeaders([segment(), segment({ index: 1 }),
    segment({ index: 2, vaddr: 0x2000n })], 128, issues);

  assert.deepEqual(issues, []);
});

for (const type of [3, 6]) {
  void test(`reports duplicate segment type ${type}`, () => {
    const issues: string[] = [];

    validateElfProgramHeaders([segment({ type }), segment({ type, index: 1 })], 128, issues);

    assert.match(issues.join(" "), /more than once/);
  });

  void test(`reports segment type ${type} following PT_LOAD`, () => {
    const issues: string[] = [];

    validateElfProgramHeaders([segment(), segment({ type, index: 1 })], 128, issues);

    assert.match(issues.join(" "), /must precede PT_LOAD/);
  });

  void test(`accepts segment type ${type} before PT_LOAD`, () => {
    const issues: string[] = [];

    validateElfProgramHeaders([segment({ type }), segment({ index: 1 })], 128, issues);

    assert.deepEqual(issues, []);
  });
}
