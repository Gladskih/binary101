"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseBaseRelocations } from "../../analyzers/pe/reloc.js";
import { MockFile } from "../helpers/mock-file.js";

type BaseRelocationBlockFixture = { pageRva: number; entries: number[]; fileOffset: number };

const rvaToOff = (rva: number): number => rva;
const IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE = 8;
// Microsoft PE format: a relocation entry packs type 3 (HIGHLOW) in the high nibble and offset 1 in the low 12 bits.
const IMAGE_REL_BASED_HIGHLOW_OFFSET_1 = 0x3001;

const writeBaseRelocationBlock = (
  view: DataView,
  fixture: BaseRelocationBlockFixture
): number => {
  const blockSize =
    IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE + fixture.entries.length * Uint16Array.BYTES_PER_ELEMENT;
  view.setUint32(fixture.fileOffset + 0, fixture.pageRva, true);
  view.setUint32(fixture.fileOffset + 4, blockSize, true);
  fixture.entries.forEach((entry, index) => {
    view.setUint16(
      fixture.fileOffset + IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE + index * Uint16Array.BYTES_PER_ELEMENT,
      entry,
      true
    );
  });
  return blockSize;
};

void test("parseBaseRelocations counts entries and stops on invalid blocks", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const directoryOffset = 0x40;
  const view = new DataView(bytes.buffer);
  const firstBlockSize = writeBaseRelocationBlock(view, {
    pageRva: 0x1000,
    entries: [0, 0, 0, 0],
    fileOffset: directoryOffset
  });
  const invalidBlockOffset = directoryOffset + firstBlockSize;
  view.setUint32(invalidBlockOffset + 0, 0x2000, true);
  view.setUint32(invalidBlockOffset + 4, 0, true);

  const parsed = await parseBaseRelocations(
    new MockFile(bytes, "reloc.bin"),
    [{ name: "BASERELOC", rva: directoryOffset, size: firstBlockSize + 8 }],
    rvaToOff
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.blocks.length, 1);
  assert.strictEqual(parsed.totalEntries, 4);
});

void test("parseBaseRelocations accepts a relocation block for page RVA 0", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const directoryOffset = 0x20;
  const view = new DataView(bytes.buffer);
  const blockSize = writeBaseRelocationBlock(view, {
    pageRva: 0,
    entries: [IMAGE_REL_BASED_HIGHLOW_OFFSET_1, 0],
    fileOffset: directoryOffset
  });

  const parsed = await parseBaseRelocations(
    new MockFile(bytes, "reloc-page-zero.bin"),
    [{ name: "BASERELOC", rva: directoryOffset, size: blockSize }],
    rvaToOff
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.blocks.length, 1);
  assert.strictEqual(parsed.blocks[0]?.pageRva, 0);
  assert.strictEqual(parsed.totalEntries, 2);
});

void test("parseBaseRelocations does not expose the second HIGHADJ slot as an independent relocation", async () => {
  const bytes = new Uint8Array(0x80).fill(0);
  const directoryOffset = 0x20;
  const view = new DataView(bytes.buffer);
  const blockSize = writeBaseRelocationBlock(view, {
    pageRva: 0x1000,
    entries: [
      0x4001,
      0x1234
    ],
    fileOffset: directoryOffset
  });

  const parsed = await parseBaseRelocations(
    new MockFile(bytes, "reloc-highadj.bin"),
    [{ name: "BASERELOC", rva: directoryOffset, size: blockSize }],
    rvaToOff
  );

  const defined = parsed;
  assert.ok(defined);
  // Microsoft PE format, Base Relocation Types:
  // IMAGE_REL_BASED_HIGHADJ occupies two WORD slots, where the second WORD carries the low 16 bits of the value
  // and is not a standalone relocation entry.
  assert.strictEqual(defined.totalEntries, 1);
  assert.strictEqual(defined.blocks[0]?.count, 1);
  assert.deepStrictEqual(defined.blocks[0]?.entries, [{ type: 4, offset: 1 }]);
});

void test("parseBaseRelocations does not silently cap valid tables at 256 blocks", async () => {
  const blockCount = 257;
  const directoryOffset = 0x40;
  const bytes = new Uint8Array(directoryOffset + blockCount * IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE).fill(0);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < blockCount; index += 1) {
    writeBaseRelocationBlock(view, {
      pageRva: 0x1000 + index * 0x1000,
      entries: [],
      fileOffset: directoryOffset + index * IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE
    });
  }

  const parsed = await parseBaseRelocations(
    new MockFile(bytes, "reloc-many-blocks.bin"),
    [{ name: "BASERELOC", rva: directoryOffset, size: blockCount * IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE }],
    rvaToOff
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.blocks.length, blockCount);
});

void test("parseBaseRelocations stops when later blocks no longer map through rvaToOff", async () => {
  const directoryRva = IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE * 4;
  const bytes = new Uint8Array(directoryRva + IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE * 2).fill(0);
  const view = new DataView(bytes.buffer);
  const firstBlockSize = writeBaseRelocationBlock(view, {
    pageRva: 0x1000,
    entries: [],
    fileOffset: directoryRva
  });
  writeBaseRelocationBlock(view, {
    pageRva: 0x2000,
    entries: [],
    fileOffset: directoryRva + firstBlockSize
  });

  const mapOnlyFirstBlock = (rva: number): number | null => (rva === directoryRva ? directoryRva : null);
  const parsed = await parseBaseRelocations(
    new MockFile(bytes, "reloc-gap.bin"),
    [{ name: "BASERELOC", rva: directoryRva, size: firstBlockSize * 2 }],
    mapOnlyFirstBlock
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.blocks.length, 1);
});

void test("parseBaseRelocations follows sparse block mappings", async () => {
  const directoryRva = 0x1000;
  const firstBlockFileOffset = 0x00;
  const secondBlockFileOffset = 0x80;
  const bytes = new Uint8Array(0x90).fill(0);
  const view = new DataView(bytes.buffer);
  const firstBlockSize = writeBaseRelocationBlock(view, {
    pageRva: 0x2000,
    entries: [],
    fileOffset: firstBlockFileOffset
  });
  const secondBlockSize = writeBaseRelocationBlock(view, {
    pageRva: 0x3000,
    entries: [IMAGE_REL_BASED_HIGHLOW_OFFSET_1],
    fileOffset: secondBlockFileOffset
  });
  const secondBlockRva = directoryRva + firstBlockSize;

  const mapSparseBaseRelocationRva = (rva: number): number | null => {
    if (rva >= directoryRva && rva < directoryRva + firstBlockSize) {
      return firstBlockFileOffset + (rva - directoryRva);
    }
    if (rva >= secondBlockRva && rva < secondBlockRva + secondBlockSize) {
      return secondBlockFileOffset + (rva - secondBlockRva);
    }
    return null;
  };

  const parsed = await parseBaseRelocations(
    new MockFile(bytes, "reloc-sparse-layout.bin"),
    [{ name: "BASERELOC", rva: directoryRva, size: firstBlockSize + secondBlockSize }],
    mapSparseBaseRelocationRva
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.blocks.length, 2);
  assert.strictEqual(parsed.totalEntries, 1);
  assert.deepStrictEqual(parsed.blocks[1]?.entries, [{ type: 3, offset: 1 }]);
});

void test("parseBaseRelocations does not assume each block maps to one contiguous file span", async () => {
  const directoryRva = 0x1000;
  const headerFileOffset = 0x10;
  const firstEntryFileOffset = 0x20;
  const secondEntryFileOffset = 0x30;
  const firstEntryRva = directoryRva + IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE;
  const secondEntryRva = firstEntryRva + Uint16Array.BYTES_PER_ELEMENT;
  const bytes = new Uint8Array(0x40).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(headerFileOffset + 0, 0x2000, true);
  view.setUint32(
    headerFileOffset + 4,
    IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE + Uint16Array.BYTES_PER_ELEMENT * 2,
    true
  );
  view.setUint16(firstEntryFileOffset, IMAGE_REL_BASED_HIGHLOW_OFFSET_1, true);
  view.setUint16(secondEntryFileOffset, 0x3002, true);

  const mapDiscontiguousRelocationRva = (rva: number): number | null => {
    if (rva >= directoryRva && rva < directoryRva + IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE) {
      return headerFileOffset + (rva - directoryRva);
    }
    if (
      rva >= firstEntryRva &&
      rva < firstEntryRva + Uint16Array.BYTES_PER_ELEMENT
    ) {
      return firstEntryFileOffset + (rva - firstEntryRva);
    }
    if (rva >= secondEntryRva && rva < secondEntryRva + Uint16Array.BYTES_PER_ELEMENT) {
      return secondEntryFileOffset + (rva - secondEntryRva);
    }
    return null;
  };

  const parsed = await parseBaseRelocations(
    new MockFile(bytes, "reloc-discontiguous-block.bin"),
    [
      {
        name: "BASERELOC",
        rva: directoryRva,
        size: IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE + Uint16Array.BYTES_PER_ELEMENT * 2
      }
    ],
    mapDiscontiguousRelocationRva
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.blocks.length, 1);
  assert.strictEqual(parsed.totalEntries, 2);
  assert.deepStrictEqual(parsed.blocks[0]?.entries, [
    { type: 3, offset: 1 },
    { type: 3, offset: 2 }
  ]);
});

void test("parseBaseRelocations does not continue from a block size that breaks 32-bit block alignment", async () => {
  const directoryOffset = 0x10;
  const misalignedBlockSize = IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE + Uint16Array.BYTES_PER_ELEMENT;
  const bytes = new Uint8Array(0x40).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(directoryOffset + 0, 0x1000, true);
  // Microsoft PE format: base relocation blocks must start on a 32-bit boundary.
  view.setUint32(directoryOffset + 4, misalignedBlockSize, true);
  view.setUint16(directoryOffset + 8, IMAGE_REL_BASED_HIGHLOW_OFFSET_1, true);
  view.setUint32(directoryOffset + 10, 0x2000, true);
  view.setUint32(directoryOffset + 14, IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE, true);

  const parsed = await parseBaseRelocations(
    new MockFile(bytes, "reloc-misaligned-block.bin"),
    [{ name: "BASERELOC", rva: directoryOffset, size: misalignedBlockSize + IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE }],
    rvaToOff
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.blocks.length, 1);
  assert.ok(parsed.warnings?.some(warning => /alignment|boundary|misaligned/i.test(warning)));
});
