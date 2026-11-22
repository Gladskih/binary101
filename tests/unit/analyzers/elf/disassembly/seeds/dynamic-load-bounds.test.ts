import assert from "node:assert/strict";
import { test } from "node:test";
import { collectElfDisassemblySeedsFromDynamic } from
  "../../../../../../analyzers/elf/disassembly-seeds-dynamic.js";
import type { ElfProgramHeader } from "../../../../../../analyzers/elf/types.js";
import { createElfGnuHashDynamicFixture } from "../../../../../fixtures/elf-gnu-hash-file.js";

const arrayFixture = (baseTag: number, sizeTag: number) => {
  const bytes = new Uint8Array(0x80);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0, 0x2000n, true);
  view.setBigUint64(8, 0x3000n, true);
  // ELF64 dynamic entries are two 8-byte words. The empty final entry is DT_NULL.
  view.setBigInt64(0x40, BigInt(baseTag), true);
  view.setBigUint64(0x48, 0x4000n, true);
  view.setBigInt64(0x50, BigInt(sizeTag), true);
  view.setBigUint64(0x58, 16n, true);
  // p_filesz cuts through the second pointer. The remainder of PT_LOAD is zero-fill.
  const load: ElfProgramHeader = { index: 0, type: 1, typeName: "PT_LOAD",
    offset: 0n, vaddr: 0x4000n, paddr: 0x4000n, filesz: 12n, memsz: 16n,
    align: 8n, flags: 4, flagNames: ["R"] };
  const dynamic = { ...load, index: 1, type: 2, typeName: "PT_DYNAMIC",
    offset: 0x40n, filesz: 0x30n, memsz: 0x30n };
  return { file: new File([bytes], "dynamic-array.elf"), programHeaders: [load, dynamic],
    is64: true, littleEndian: true, issues: [] as string[] };
};

// gABI §8.3: DT_*_ARRAY points to pointers, and DT_*_ARRAYSZ gives bytes.
for (const [source, baseTag, sizeTag] of [
  ["DT_PREINIT_ARRAY", 32, 33], ["DT_INIT_ARRAY", 25, 27], ["DT_FINI_ARRAY", 26, 28]
] as const) {
  void test(`${source} reads only complete pointers within p_filesz`, async () => {
    const fixture = arrayFixture(baseTag, sizeTag);

    const groups = await collectElfDisassemblySeedsFromDynamic(fixture);

    assert.deepEqual(groups, [{ source, vaddrs: [0x2000n] }]);
    assert.match(fixture.issues.join(" "), new RegExp(`${source}.*file-backed PT_LOAD`));
  });
}

void test("does not seed a dynamic symbol from bytes beyond p_filesz", async () => {
  const fixture = createElfGnuHashDynamicFixture();
  fixture.programHeaders[0]!.filesz = 0x90n; // Hash fits. Symbol #1 at file offset 0xd8 does not.
  const issues: string[] = [];

  const groups = await collectElfDisassemblySeedsFromDynamic({
    ...fixture, is64: true, littleEndian: true, issues
  });

  assert.deepEqual(groups, []);
  assert.match(issues.join(" "), /DT_SYMTAB.*file-backed PT_LOAD/);
});
