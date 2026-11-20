import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfDynamicSymbols } from "../../../../analyzers/elf/dynamic-symbols.js";
import { createElfGnuHashDynamicFixture } from "../../../fixtures/elf-gnu-hash-file.js";

void test("empty GNU hash does not determine how many imports precede the hash range", async () => {
  const fixture = createElfGnuHashDynamicFixture("empty");
  // GNU ld writes one zero bucket and symoffset=1 when no symbol can be hashed.
  const result = await parseElfDynamicSymbols({ file: fixture.file,
    programHeaders: fixture.programHeaders, sections: [], is64: true, littleEndian: true });

  assert.equal(result?.total, 2);
  assert.equal(result.importSymbols[0]?.name, fixture.symbolName);
  assert.match(result.issues.join(" "), /count inferred/);
});

void test("DT_SYMTABSZ bounds a sectionless table with its strings before its symbols", async () => {
  const fixture = createElfGnuHashDynamicFixture("declared-size");
  const result = await parseElfDynamicSymbols({ file: fixture.file,
    programHeaders: fixture.programHeaders, sections: [], is64: true, littleEndian: true });

  assert.equal(result?.total, 2);
  assert.equal(result.exportSymbols[0]?.name, fixture.symbolName);
  assert.deepEqual(result.issues, []);
});

// Empty, misaligned, and aligned but larger than a file-backed range.
for (const byteSize of [0n, 25n, 0xffffffffffffffd8n]) {
  void test(`invalid declared dynamic symbol table size ${byteSize} is diagnosed`, async () => {
    const fixture = createElfGnuHashDynamicFixture("declared-size");
    const bytes = await fixture.file.arrayBuffer();
    // Fixture's fifth Elf64_Dyn holds DT_SYMTABSZ, with d_val at +8.
    new DataView(bytes).setBigUint64(0x120 + 4 * 16 + 8, byteSize, true);
    const result = await parseElfDynamicSymbols({ file: new File([bytes], "size.elf"),
      programHeaders: fixture.programHeaders, sections: [], is64: true, littleEndian: true });

    assert.equal(result?.total, 0);
    assert.match(result.issues.join(" "), /DT_SYMTABSZ/);
  });
}
