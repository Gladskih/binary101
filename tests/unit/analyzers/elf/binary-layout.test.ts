import assert from "node:assert/strict";
import { test } from "node:test";
import { selectElfBinaryLayout } from "../../../../analyzers/elf/binary-layout.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

for (const bits of [32, 64] as const) {
  for (const order of ["little", "big"] as const) {
    void test(`ELF${bits} ${order} layout decodes independent ABI records`, () => {
      const fixture = relocationFixture(bits, order);
      const layout = selectElfBinaryLayout(fixture.elf);
      const wordSize = bits / 8;
      fixture.word(64, 8n);
      fixture.word(64 + wordSize, (3n << BigInt(bits === 64 ? 32 : 8)) | 2n);
      fixture.word(64 + wordSize * 2, -7n);
      // gABI Elf32/64_Rel[a]: address, r_info and optional signed addend.
      const record = new DataView(fixture.bytes.buffer, 64, wordSize * 3);

      assert.equal(layout.wordSize, wordSize);
      // gABI Elf32_Ehdr is 52 bytes; Elf64_Ehdr is 64 bytes (§2.1).
      assert.equal(fixture.elf.header.ehsize, bits === 64 ? 64 : 52);
      assert.equal(layout.byteOrder, order);
      assert.deepEqual(layout.relocations.REL.read(new DataView(
        fixture.bytes.buffer, 64, wordSize * 2)),
        { offset: 8n, type: 2, symbolIndex: 3, addend: null });
      assert.deepEqual(layout.relocations.RELA.read(record),
        { offset: 8n, type: 2, symbolIndex: 3, addend: -7n });
      assert.equal(layout.readWord(new DataView(fixture.bytes.buffer, 64, wordSize)), 8n);
      // SHT_SYMTAB_SHNDX entries are Elf32_Word in both ELF classes (gABI §5).
      assert.equal(layout.readSectionIndex(new DataView(fixture.bytes.buffer, 64, 4)),
        bits === 64 && order === "big" ? 0 : 8);
      assert.equal(layout.relocations.REL.entrySize, wordSize * 2);
      assert.equal(layout.relocations.RELA.entrySize, wordSize * 3);
      assert.deepEqual(layout.readDynamic(new DataView(fixture.bytes.buffer, 64, wordSize * 2)),
        { tag: 8n, value: (3n << BigInt(bits === 64 ? 32 : 8)) | 2n });
      assert.deepEqual(layout.readSymbol(new DataView(fixture.bytes.buffer,
        256 + (bits === 64 ? 24 : 16), bits === 64 ? 24 : 16)),
      { nameOffset: 1, value: 4n, size: 0n, info: 0, other: 0, sectionIndex: 1 });
    });

    void test(`ELF${bits} ${order} rejects truncated records`, () => {
      const layout = selectElfBinaryLayout(relocationFixture(bits, order).elf);
      const wordSize = bits / 8;
      // One byte short of each ABI structure, including the class-independent
      // 4-byte extended symbol index: https://gabi.xinuos.com/elf/05-symtab.html
      const truncated = (size: number): DataView => new DataView(new ArrayBuffer(size - 1));

      assert.equal(layout.readDynamic(truncated(wordSize * 2)), null);
      assert.equal(layout.readSymbol(truncated(bits === 64 ? 24 : 16)), null);
      assert.equal(layout.relocations.REL.read(truncated(wordSize * 2)), null);
      assert.equal(layout.relocations.RELA.read(truncated(wordSize * 3)), null);
      assert.equal(layout.readWord(truncated(wordSize)), null);
      assert.equal(layout.readSectionIndex(truncated(4)), null);
    });
  }
}
