import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { parseElfDynamicSymbols } from "../../../../analyzers/elf/dynamic-symbols.js";
import { createElfDynsymBindingValidator } from "../../../../analyzers/elf/dynamic-symbol-validation.js";
import type { ElfHashTable } from "../../../../analyzers/elf/hash-types.js";
import { createElfGnuHashDynamicFixture } from "../../../fixtures/elf-gnu-hash-file.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const nullSymbol = { nameOffset: 0, value: 0n, size: 0n, info: 0, other: 0, sectionIndex: 0 };

void test("requires the null symbol even in an empty complete table", () => {
  const issues: string[] = [];

  createElfDynsymBindingValidator(undefined, issues).finish(0);

  assert.deepEqual(issues, [".dynsym is missing symbol #0 (STN_UNDEF)."]);
});

void test("retains the only proven boundary finding when a table is truncated", () => {
  const issues: string[] = [];
  const validator = createElfDynsymBindingValidator(0, issues);
  validator.record(0, nullSymbol);

  validator.finish(undefined);

  assert.deepEqual(issues, [".dynsym sh_info (0) disagrees with the local symbol boundary."]);
});

void test("does not infer a local boundary from the end of a truncated prefix", () => {
  const issues: string[] = [];
  const validator = createElfDynsymBindingValidator(4, issues);
  validator.record(0, nullSymbol);

  validator.finish(undefined);

  assert.deepEqual(issues, []);
});

void test("reports a local-after-global contradiction just once", () => {
  const issues: string[] = [];
  const validator = createElfDynsymBindingValidator(1, issues);
  validator.record(0, nullSymbol);
  validator.record(1, { ...nullSymbol, info: 0x10 });
  validator.record(2, nullSymbol);
  validator.record(3, nullSymbol);

  validator.finish(4);

  assert.deepEqual(issues, ["Local dynamic symbol #2 follows a nonlocal symbol (#1)."]);
});

// gABI 5.3/5.6: index zero is all zero and locals precede nonlocals.
for (const [info, other, lastBinding, warning] of [
  [1, 0, 0x12, null],
  [1, 1, 0x12, /STN_UNDEF/],
  [0, 0, 0x12, /sh_info/],
  [2, 0, 0x12, /sh_info/],
  [4, 0, 0x12, /sh_info/],
  [1, 0, 0x03, /local.*follows a nonlocal/i]
] as const) {
  void test(`checks dynsym boundary ${info}, entry zero and binding order: ${warning}`, async () => {
    const { file } = createElfMetadataFile();
    const elf = expectDefined(await parseElf(file));
    const dynsym = expectDefined(elf.sections.find(section => section.type === 11));
    const bytes = new Uint8Array(await file.arrayBuffer());
    bytes[Number(dynsym.offset) + 5] = other; // Elf64_Sym st_other.
    bytes[Number(dynsym.offset) + 2 * 24 + 4] = lastBinding; // Elf64_Sym st_info.
    dynsym.info = info;

    const result = await parseElfDynamicSymbols({ ...elf, file: new File([bytes], "bindings.elf") });

    assert.equal(result?.total, 3);
    assert.equal(warning ? result?.issues.some(issue => warning.test(issue)) : !result?.issues.length, true);
  });
}

// GNU hash of the raw byte FF is 5381 * 33 + 255 = 177828.
for (const reachable of [true, false]) {
  void test(`validates GNU hash for a raw non-UTF-8 name (reachable: ${reachable})`, async () => {
    const fixture = createElfGnuHashDynamicFixture();
    const bytes = new Uint8Array(await fixture.file.arrayBuffer());
    bytes.set([0xff, 0], 0x41); // This fixture's name starts one byte into .dynstr.
    const hash: ElfHashTable = { kind: "gnu", offset: 0x80, symbolOffset: 1,
      bloomShift: 0, bloom: [1n << 36n], buckets: reachable ? [1, 0] : [0, 1],
      chains: [177829], issues: [] };

    const result = await parseElfDynamicSymbols({ ...fixture, file: new File([bytes], "raw-name"),
      sections: [], is64: true, littleEndian: true }, undefined, undefined, undefined, [hash]);

    assert.equal(result?.exportSymbols[0]?.name, "\ufffd");
    assert.deepEqual(hash.issues.map(issue => /unreachable.*bucket 0/i.test(issue)),
      reachable ? [] : [true]);
  });
}
