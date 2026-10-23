import assert from "node:assert/strict";
import type { RvaToOffset } from "../../../analyzers/pe/types.js";

interface DescriptorBlock {
  begin: number;
  end: number;
  bytes: Uint8Array;
}

const collectBlocks = (image: Uint8Array, rows: readonly (readonly number[])[],
  rvaToOff: RvaToOffset): DescriptorBlock[] => {
  const seen = new Set<number>();
  const blocks: DescriptorBlock[] = [];
  for (const row of rows) {
    if (seen.has(row[2]!)) continue;
    seen.add(row[2]!);
    const offset = rvaToOff(row[2]!);
    assert.ok(offset != null && offset + 8 <= image.length);
    const header = new DataView(image.buffer, image.byteOffset + offset, 8);
    assert.equal(header.getUint16(0, true), 3);
    const length = header.getUint32(4, true) * 8;
    assert.ok(offset + 8 + length <= image.length);
    const bytes = Uint8Array.from(image.subarray(offset, offset + 8 + length));
    // Translate only the Windows container header to the ELF ABI. GNU receives
    // exactly the original descriptor bytes, without a personality/LSDA trailer.
    new DataView(bytes.buffer).setBigUint64(0, (1n << 48n) | BigInt(length / 8), true);
    assert.deepEqual(bytes.subarray(8), Uint8Array.from(image.subarray(offset + 8, offset + 8 + length)));
    blocks.push({ begin: row[0]!, end: row[1]!, bytes });
  }
  return blocks;
};

const writeSection = (view: DataView, index: number, name: number, type: number,
  address: number, offset: number, size: number): void => {
  const location = 64 + index * 64;
  view.setUint32(location, name, true);
  view.setUint32(location + 4, type, true);
  view.setBigUint64(location + 8, index === 3 ? 0n : 2n, true); // SHF_ALLOC.
  view.setBigUint64(location + 16, BigInt(address), true);
  view.setBigUint64(location + 24, BigInt(offset), true);
  view.setBigUint64(location + 32, BigInt(size), true);
  view.setBigUint64(location + 48, 8n, true);
};

const writeElfHeader = (bytes: Uint8Array): void => {
  const view = new DataView(bytes.buffer);
  bytes.set([0x7f, 69, 76, 70, 2, 1, 1]); // ELF64, little-endian, version 1.
  view.setUint16(16, 2, true);
  view.setUint16(18, 50, true); // EM_IA_64.
  view.setUint32(20, 1, true);
  view.setBigUint64(40, 64n, true);
  view.setUint16(52, 64, true);
  view.setUint16(58, 64, true);
  view.setUint16(60, 4, true);
  view.setUint16(62, 3, true);
};

export const createIa64DescriptorElf = (image: Uint8Array, rows: readonly (readonly number[])[],
  rvaToOff: RvaToOffset): Uint8Array => {
  const blocks = collectBlocks(image, rows, rvaToOff);
  const names = "\0.IA_64.unwind\0.IA_64.unwind_info\0.shstrtab\0";
  const tableOffset = 64 + 4 * 64;
  const infoOffset = tableOffset + blocks.length * 24;
  const infoSize = blocks.reduce((sum, block) => sum + block.bytes.length, 0);
  const namesOffset = infoOffset + infoSize;
  const bytes = new Uint8Array(namesOffset + names.length);
  const view = new DataView(bytes.buffer);
  writeElfHeader(bytes);
  writeSection(view, 1, names.indexOf(".IA_64.unwind"), 0x70000001, 0x100000, tableOffset, blocks.length * 24);
  view.setUint32(64 + 64 + 40, 2, true); // sh_link identifies the unwind-info section.
  view.setBigUint64(64 + 64 + 56, 24n, true);
  writeSection(view, 2, names.indexOf(".IA_64.unwind_info"), 1, 0x200000, infoOffset, infoSize);
  writeSection(view, 3, names.indexOf(".shstrtab"), 3, 0, namesOffset, names.length);
  let position = infoOffset;
  blocks.forEach((block, index) => {
    view.setBigUint64(tableOffset + index * 24, BigInt(block.begin), true);
    view.setBigUint64(tableOffset + index * 24 + 8, BigInt(block.end), true);
    view.setBigUint64(tableOffset + index * 24 + 16, BigInt(0x200000 + position - infoOffset), true);
    bytes.set(block.bytes, position);
    position += block.bytes.length;
  });
  bytes.set(new TextEncoder().encode(names), namesOffset);
  return bytes;
};

export const readGnuIa64Statistics = (text: string): Record<string, number> => {
  const counts: Record<string, number> = {};
  const categories: Record<string, string> = { mem_stack_f: "Fixed stack allocations",
    mem_stack_v: "Variable stack allocations", spill_base: "Spill-base changes",
    label_state: "Saved-state labels", copy_state: "Saved-state copies", epilogue: "Epilogues",
    spill_mask: "Spill schedules", abi: "ABI context records" };
  for (const row of text.matchAll(/^\s*(R[1-3]|P(?:10|[1-9])|B[1-4]|X[1-4]):([a-z0-9_]+)\(([^\n]*)/gm)) {
    const region = row[2]!.startsWith("prologue")
      ? /rlen=0\b/.test(row[3]!) ? "Empty prologues / padding" : "Prologue regions" : "Body regions";
    const kind = row[1]![0] === "R" ? region : categories[row[2]!] ?? "Register rules";
    counts[kind] = (counts[kind] ?? 0) + 1;
  }
  return counts;
};
