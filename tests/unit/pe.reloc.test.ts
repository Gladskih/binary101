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

void test("parseBaseRelocations reports an unmappable directory base instead of silently returning null", async () => {
  const parsed = await parseBaseRelocations(
    new MockFile(
      new Uint8Array(IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE).fill(0),
      "reloc-unmapped.bin"
    ),
    [{ name: "BASERELOC", rva: 1, size: IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE }],
    () => null
  );

  assert.ok(parsed);
  assert.deepStrictEqual(parsed?.blocks, []);
  assert.strictEqual(parsed?.totalEntries, 0);
  assert.ok(parsed?.warnings?.some(warning => /map|offset|rva/i.test(warning)));
});

void test("parseBaseRelocations preserves a non-zero directory that is smaller than one block header", async () => {
  const parsed = await parseBaseRelocations(
    new MockFile(
      new Uint8Array(IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE - 1).fill(0),
      "reloc-too-small.bin"
    ),
    [{ name: "BASERELOC", rva: 1, size: IMAGE_BASE_RELOCATION_BLOCK_HEADER_SIZE - 1 }],
    rvaToOff
  );

  assert.ok(parsed);
  assert.deepStrictEqual(parsed?.blocks, []);
  assert.strictEqual(parsed?.totalEntries, 0);
  assert.ok(parsed?.warnings?.some(warning => /smaller|header|8-byte|truncated/i.test(warning)));
});

void test("parseBaseRelocations warns when a relocation block size runs past the declared directory span", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const directoryOffset = 0x20;
  const view = new DataView(bytes.buffer);
  const blockSize = writeBaseRelocationBlock(view, {
    pageRva: 0x1000,
    entries: [IMAGE_REL_BASED_HIGHLOW_OFFSET_1, 0x3002],
    fileOffset: directoryOffset
  });

  const parsed = await parseBaseRelocations(
    new MockFile(bytes, "reloc-truncated-block.bin"),
    // Microsoft PE format: Block Size is the total byte size of the relocation block.
    // A block whose own header overruns the relocation directory should stay visible but emit a warning.
    [{ name: "BASERELOC", rva: directoryOffset, size: blockSize - Uint16Array.BYTES_PER_ELEMENT }],
    rvaToOff
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.blocks.length, 1);
  assert.ok(parsed.warnings?.some(warning => /trunc/i.test(warning)));
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
