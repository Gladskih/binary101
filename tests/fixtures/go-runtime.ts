"use strict";

import { SUPPORTED_GO_RUNTIME_LAYOUTS } from "../../analyzers/go-runtime/layouts.js";
import type { GoRuntimeAddressSpace, GoRuntimeLayout } from "../../analyzers/go-runtime/types.js";

export interface GoRuntimeFixture {
  image: GoRuntimeAddressSpace;
  pcHeaderAddress: bigint;
  moduleDataAddress: bigint;
  textAddress: bigint;
  headerBytes: Uint8Array;
  moduleBytes: Uint8Array;
  regions: Array<{ address: bigint; bytes: Uint8Array; executable: boolean }>;
}

const align = (value: number, alignment: number): number =>
  Math.ceil(value / alignment) * alignment;

const writeWord = (
  view: DataView,
  offset: number,
  value: bigint,
  pointerSize: 4 | 8
): void => {
  if (pointerSize === 8) view.setBigUint64(offset, value, true);
  else view.setUint32(offset, Number(value), true);
};

const writeSlice = (
  view: DataView,
  word: number,
  address: bigint,
  length: number,
  pointerSize: 4 | 8
): void => {
  writeWord(view, word * pointerSize, address, pointerSize);
  writeWord(view, (word + 1) * pointerSize, BigInt(length), pointerSize);
  writeWord(view, (word + 2) * pointerSize, BigInt(length), pointerSize);
};

const encoded = (value: string): Uint8Array => new TextEncoder().encode(value);

const createAddressSpace = (
  regions: GoRuntimeFixture["regions"],
  pointerSize: 4 | 8
): GoRuntimeAddressSpace => {
  const containing = (address: bigint, size: number) => regions.find(region =>
    address >= region.address && address + BigInt(size) <= region.address + BigInt(region.bytes.length)
  );
  return {
    pointerSize,
    isMappedRange: (address, size) => containing(address, size) != null,
    isExecutableRange: (start, end) => containing(start, Number(end - start))?.executable === true,
    readMapped: async (address, size) => {
      const region = containing(address, size);
      if (!region) return null;
      const offset = Number(address - region.address);
      return region.bytes.slice(offset, offset + size);
    }
  };
};

// Exact functab/_func field widths and offsets follow the official runtime definitions:
// https://github.com/golang/go/blob/go1.16.15/src/runtime/symtab.go
// https://github.com/golang/go/blob/go1.26.4/src/runtime/symtab.go
const writeFunctionTable = (
  bytes: Uint8Array,
  textAddress: bigint,
  layout: GoRuntimeLayout,
  pointerSize: 4 | 8
): void => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (layout === "go1.16-1.17") {
    writeWord(view, 0, textAddress, pointerSize);
    writeWord(view, pointerSize, 40n, pointerSize);
    writeWord(view, pointerSize * 2, textAddress + 0x20n, pointerSize);
    writeWord(view, pointerSize * 3, 56n, pointerSize);
    writeWord(view, pointerSize * 4, textAddress + 0x40n, pointerSize);
    writeWord(view, 40, textAddress, pointerSize);
    view.setInt32(40 + pointerSize, 0, true);
    writeWord(view, 56, textAddress + 0x20n, pointerSize);
    view.setInt32(56 + pointerSize, 13, true);
    return;
  }
  view.setUint32(0, 0, true);
  view.setUint32(4, 24, true);
  view.setUint32(8, 0x20, true);
  view.setUint32(12, 32, true);
  view.setUint32(16, 0x40, true);
  view.setUint32(24, 0, true);
  view.setInt32(28, 0, true);
  view.setUint32(32, 0x20, true);
  view.setInt32(36, 13, true);
};

export const createGoRuntimeFixture = (
  layoutId: GoRuntimeLayout,
  pointerSize: 4 | 8 = 8,
  imageBase = 0x1400_0000_0n
): GoRuntimeFixture => {
  // pcHeader/moduledata word order follows runtime.symtab and cmd/link's generated pclntab:
  // https://github.com/golang/go/blob/go1.26.4/src/cmd/link/internal/ld/pcln.go
  const layout = SUPPORTED_GO_RUNTIME_LAYOUTS.find(candidate => candidate.id === layoutId)!;
  const textAddress = imageBase + 0x1000n;
  const pcHeaderAddress = imageBase + 0x2000n;
  const moduleDataAddress = imageBase + 0x3000n;
  const functionNames = encoded("runtime.main\0main.main\0");
  const files = encoded("runtime/proc.go\0hello.go\0");
  const headerSize = 8 + layout.headerWordCount * pointerSize;
  const functionNameOffset = align(headerSize, pointerSize);
  const compilationUnitOffset = align(functionNameOffset + functionNames.length, pointerSize);
  const fileOffset = compilationUnitOffset + 8;
  const pcTableOffset = fileOffset + files.length;
  const pclnOffset = align(pcTableOffset + 1, 4);
  const pclnLength = layoutId === "go1.16-1.17" ? 68 : 40;
  const headerBytes = new Uint8Array(pclnOffset + pclnLength);
  const headerView = new DataView(headerBytes.buffer);
  headerView.setUint32(0, layout.magic, true);
  headerView.setUint8(6, 1);
  headerView.setUint8(7, pointerSize);
  writeWord(headerView, 8, 2n, pointerSize);
  writeWord(headerView, 8 + pointerSize, 2n, pointerSize);
  if (layout.relativeFunctionEntries) writeWord(headerView, 8 + pointerSize * 2, textAddress, pointerSize);
  [functionNameOffset, compilationUnitOffset, fileOffset, pcTableOffset, pclnOffset]
    .forEach((offset, index) => writeWord(
      headerView,
      8 + (layout.tableOffsetWord + index) * pointerSize,
      BigInt(offset),
      pointerSize
    ));
  headerBytes.set(functionNames, functionNameOffset);
  headerView.setUint32(compilationUnitOffset, 0, true);
  headerView.setUint32(compilationUnitOffset + 4, 16, true);
  headerBytes.set(files, fileOffset);
  headerBytes[pcTableOffset] = 0;
  writeFunctionTable(headerBytes.subarray(pclnOffset), textAddress, layoutId, pointerSize);
  const moduleBytes = new Uint8Array(24 * pointerSize);
  const moduleView = new DataView(moduleBytes.buffer);
  writeWord(moduleView, 0, pcHeaderAddress, pointerSize);
  const tableOffsets = [functionNameOffset, compilationUnitOffset, fileOffset, pcTableOffset, pclnOffset];
  const tableLengths = [functionNames.length, 2, files.length, 1, pclnLength];
  tableOffsets.forEach((offset, index) => writeSlice(
    moduleView,
    1 + index * 3,
    pcHeaderAddress + BigInt(offset),
    tableLengths[index]!,
    pointerSize
  ));
  writeSlice(moduleView, 16, pcHeaderAddress + BigInt(pclnOffset), 3, pointerSize);
  writeWord(moduleView, 19 * pointerSize, pcHeaderAddress, pointerSize);
  writeWord(moduleView, 20 * pointerSize, textAddress, pointerSize);
  writeWord(moduleView, 21 * pointerSize, textAddress + 0x40n, pointerSize);
  writeWord(moduleView, 22 * pointerSize, textAddress, pointerSize);
  writeWord(moduleView, 23 * pointerSize, textAddress + 0x40n, pointerSize);
  const regions = [
    { address: textAddress, bytes: new Uint8Array(0x40), executable: true },
    { address: pcHeaderAddress, bytes: headerBytes, executable: false },
    { address: moduleDataAddress, bytes: moduleBytes, executable: false }
  ];
  return {
    image: createAddressSpace(regions, pointerSize),
    pcHeaderAddress,
    moduleDataAddress,
    textAddress,
    headerBytes,
    moduleBytes,
    regions
  };
};
