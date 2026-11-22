import assert from "node:assert/strict";
import { test } from "node:test";
import { elfDynamicSymbolTags } from "../../../../analyzers/elf/dynamic-symbol-tags.js";

// gABI 8.3: DT_STRTAB=5, DT_SYMTAB=6, DT_STRSZ=10, DT_SYMENT=11 and DT_SYMTABSZ=39.
const symbolTags = (stride: number) => [
  { tag: 5, value: BigInt(stride) }, { tag: 6, value: 0n },
  { tag: 10, value: 0n }, { tag: 11, value: BigInt(stride) }, { tag: 39, value: BigInt(stride) }
];

for (const stride of [16, 24]) { // Elf32_Sym and Elf64_Sym, gABI 5.1.
  void test(`takes an ELF symbol stride of ${stride} and preserves zero-valued tags`, () => {
    const issues: string[] = [];

    const result = elfDynamicSymbolTags({ entries: symbolTags(stride), terminated: true }, stride, issues);

    assert.deepEqual(issues, []);
    assert.deepEqual(result,
      { symtabVaddr: 0n, strtabVaddr: BigInt(stride), strsz: 0n, entrySize: stride, declaredSize: BigInt(stride) });
  });
}

for (const [tag, warning] of [
  [5, undefined], [6, "Conflicting DT_SYMTAB values."],
  [10, undefined], [11, "Conflicting DT_SYMENT values."], [39, "Conflicting DT_SYMTABSZ values."]
] as const) {
  void test(`does not choose an arbitrary value for conflicting runtime symbol table tag ${tag}`, () => {
    const entries = [...symbolTags(24), { tag, value: 1n }];
    const issues: string[] = [];

    assert.equal(elfDynamicSymbolTags({ entries, terminated: true }, 24, issues), null);
    assert.deepEqual(issues, warning ? [warning] : []);
  });
}

for (const tag of [5, 6, 10]) {
  void test(`cannot locate the runtime symbol table with tag ${tag} absent`, () => {
    const entries = symbolTags(24).filter(entry => entry.tag !== tag);

    assert.equal(elfDynamicSymbolTags({ entries, terminated: true }, 24, []), null);
  });
}

void test("a runtime symbol table can be located without a declared total size", () => {
  const entries = symbolTags(24).filter(entry => entry.tag !== 39);

  assert.deepEqual(elfDynamicSymbolTags({ entries, terminated: true }, 24, []),
    { symtabVaddr: 0n, strtabVaddr: 24n, strsz: 0n, entrySize: 24, declaredSize: undefined });
});
