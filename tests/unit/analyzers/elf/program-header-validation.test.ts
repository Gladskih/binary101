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

for (const [fields, secondStart, warning] of [
  [{}, 64n, null],
  [{ offset: 31n }, 64n, /PT_PHDR.*e_phoff/],
  [{ filesz: 95n }, 64n, /PT_PHDR.*p_filesz/],
  [{ memsz: 97n }, 64n, /PT_PHDR.*p_memsz/],
  [{ vaddr: 0x2020n }, 64n, /PT_PHDR.*file-backed PT_LOAD/],
  [{}, 65n, /PT_PHDR.*file-backed PT_LOAD/]
] as const) {
  void test(`cross-checks program table dimensions and mapping: ${warning}`, () => {
    const issues: string[] = [];
    const phdr = segment({ type: 6, offset: 32n, vaddr: 0x1020n,
      filesz: 96n, memsz: 96n, ...fields });
    const loads = [segment({ index: 1 }), segment({ index: 2, offset: secondStart,
      vaddr: 0x1000n + secondStart, filesz: 128n - secondStart })];

    validateElfProgramHeaders([phdr, ...loads], 128, issues,
      { phoff: 32n, phentsize: 32, phnum: 3 });

    assert.deepEqual(issues.map(issue => warning?.test(issue)), warning ? [true] : []);
  });
}

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

void test("does not mistake an out-of-file table for a missing memory mapping", () => {
  const issues: string[] = [];
  const phdr = segment({ type: 6, offset: 32n, vaddr: 0x1020n, filesz: 64n, memsz: 64n });

  validateElfProgramHeaders([phdr], 64, issues, { phoff: 32n, phentsize: 32, phnum: 2 });

  assert.deepEqual(issues, ["Segment #0 file range is outside the file."]);
});

void test("does not add a redundant mapping finding for an incorrectly sized PT_PHDR", () => {
  const issues: string[] = [];
  const phdr = segment({ type: 6, offset: 32n, vaddr: 0x1020n, filesz: 32n, memsz: 32n });

  validateElfProgramHeaders([phdr], 96, issues, { phoff: 32n, phentsize: 32, phnum: 2 });

  assert.deepEqual(issues, [
    "PT_PHDR #0: p_filesz differs from the program header table size.",
    "PT_PHDR #0: p_memsz differs from the program header table size."
  ]);
});

void test("a load with a short memory extent cannot cover the table even if its file range does", () => {
  const issues: string[] = [];
  const phdr = segment({ type: 6, offset: 32n, vaddr: 0x1020n, filesz: 64n, memsz: 64n });
  const load = segment({ index: 1, filesz: 96n, memsz: 64n });

  validateElfProgramHeaders([phdr, load], 96, issues, { phoff: 32n, phentsize: 32, phnum: 2 });

  assert.deepEqual(issues, ["PT_LOAD #1: p_filesz exceeds p_memsz.",
    "PT_PHDR #0: the program header table lacks file-backed PT_LOAD coverage at p_vaddr."]);
});

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

void test("ignores non-load addresses and positions when checking segment ordering", () => {
  const issues: string[] = [];

  validateElfProgramHeaders([segment({ type: 4 }), segment({ index: 1, type: 3 }),
    segment({ index: 2 }), segment({ index: 3, type: 4, vaddr: 0n }),
    segment({ index: 4, vaddr: 0x2000n })], 128, issues);

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
