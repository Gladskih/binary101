"use strict";

import { findGoRuntimeLayout, type GoRuntimeLayoutDefinition } from "./layouts.js";
import type {
  GoRuntimeAddressSpace,
  GoRuntimeFunction,
  GoRuntimeMetadata
} from "./types.js";
import { readExact, readWord, toView } from "./memory.js";
import { parseGoFunctions, validateGoFileTables } from "./tables.js";
import {
  GO_RUNTIME_MAX_ENTRY_COUNT,
  GO_RUNTIME_MAX_TABLE_BYTE_LENGTH
} from "./limits.js";

export interface PcHeader {
  address: bigint;
  layout: GoRuntimeLayoutDefinition;
  functionCount: number;
  fileCount: number;
  textField: bigint | null;
  tableOffsets: bigint[];
}

export interface GoSlice {
  address: bigint;
  length: number;
  capacity: number;
}

export interface ModuleDataPrefix {
  slices: GoSlice[];
  findFuncTable: bigint;
  minPc: bigint;
  maxPc: bigint;
  text: bigint;
  textEnd: bigint;
}

const safeCount = (value: bigint, limit: number): number | null =>
  value > 0n && value <= BigInt(limit) ? Number(value) : null;

const parseHeaderWords = (
  view: DataView,
  address: bigint,
  layout: GoRuntimeLayoutDefinition,
  pointerSize: 4 | 8
): PcHeader | null => {
  const functionCount = safeCount(readWord(view, 8, pointerSize), GO_RUNTIME_MAX_ENTRY_COUNT);
  const fileCount = safeCount(readWord(view, 8 + pointerSize, pointerSize), GO_RUNTIME_MAX_ENTRY_COUNT);
  if (functionCount == null || fileCount == null) return null;
  const words = Array.from({ length: layout.headerWordCount }, (_, index) =>
    readWord(view, 8 + index * pointerSize, pointerSize)
  );
  const tableOffsets = words.slice(layout.tableOffsetWord);
  if (tableOffsets.length !== 5) return null;
  if (tableOffsets.some(
    offset => offset <= 0n || offset > BigInt(GO_RUNTIME_MAX_TABLE_BYTE_LENGTH)
  )) return null;
  if (tableOffsets.some((offset, index) => index > 0 && offset <= tableOffsets[index - 1]!)) return null;
  return {
    address,
    layout,
    functionCount,
    fileCount,
    textField: layout.relativeFunctionEntries ? words[2] ?? null : null,
    tableOffsets
  };
};

export const parseGoPcHeader = async (
  image: GoRuntimeAddressSpace,
  address: bigint
): Promise<PcHeader | null> => {
  const prefix = await readExact(image, address, 8);
  if (!prefix) return null;
  const view = toView(prefix);
  const layout = findGoRuntimeLayout(view.getUint32(0, true));
  if (!layout || view.getUint8(4) !== 0 || view.getUint8(5) !== 0) return null;
  if (![1, 2, 4].includes(view.getUint8(6)) || view.getUint8(7) !== image.pointerSize) return null;
  const wordBytes = await readExact(
    image,
    address + 8n,
    layout.headerWordCount * image.pointerSize
  );
  if (!wordBytes) return null;
  const bytes = new Uint8Array(8 + wordBytes.byteLength);
  bytes.set(prefix);
  bytes.set(wordBytes, 8);
  return parseHeaderWords(toView(bytes), address, layout, image.pointerSize);
};

const parseSlice = (view: DataView, word: number, pointerSize: 4 | 8): GoSlice | null => {
  const offset = word * pointerSize;
  const address = readWord(view, offset, pointerSize);
  const length = safeCount(
    readWord(view, offset + pointerSize, pointerSize),
    GO_RUNTIME_MAX_TABLE_BYTE_LENGTH
  );
  const capacity = safeCount(
    readWord(view, offset + pointerSize * 2, pointerSize),
    GO_RUNTIME_MAX_TABLE_BYTE_LENGTH
  );
  return length != null && capacity != null && length === capacity
    ? { address, length, capacity }
    : null;
};

const parseModuleDataPrefix = async (
  image: GoRuntimeAddressSpace,
  address: bigint,
  headerAddress: bigint
): Promise<ModuleDataPrefix | null> => {
  // Go 1.16-current moduledata has 24 pointer-sized words through text/etext:
  // https://github.com/golang/go/blob/go1.26.4/src/runtime/symtab.go
  const bytes = await readExact(image, address, 24 * image.pointerSize);
  if (!bytes) return null;
  const view = toView(bytes);
  if (readWord(view, 0, image.pointerSize) !== headerAddress) return null;
  const sliceWords = [1, 4, 7, 10, 13, 16];
  const slices = sliceWords.map(word => parseSlice(view, word, image.pointerSize));
  if (slices.some(slice => slice == null)) return null;
  return {
    slices: slices as GoSlice[],
    findFuncTable: readWord(view, 19 * image.pointerSize, image.pointerSize),
    minPc: readWord(view, 20 * image.pointerSize, image.pointerSize),
    maxPc: readWord(view, 21 * image.pointerSize, image.pointerSize),
    text: readWord(view, 22 * image.pointerSize, image.pointerSize),
    textEnd: readWord(view, 23 * image.pointerSize, image.pointerSize)
  };
};

const sliceByteSize = (slice: GoSlice, elementSize: number): number | null => {
  const size = slice.length * elementSize;
  return Number.isSafeInteger(size) && size <= GO_RUNTIME_MAX_TABLE_BYTE_LENGTH ? size : null;
};

const validateSlices = (
  image: GoRuntimeAddressSpace,
  header: PcHeader,
  moduleData: ModuleDataPrefix
): boolean => {
  const [functionNames, compilationUnits, files, pcTable, pclnTable, functionTable] =
    moduleData.slices;
  if (!functionNames || !compilationUnits || !files || !pcTable || !pclnTable || !functionTable) return false;
  const expectedAddresses = header.tableOffsets.map(offset => header.address + offset);
  const tableSlices = [functionNames, compilationUnits, files, pcTable, pclnTable];
  if (tableSlices.some((slice, index) => slice.address !== expectedAddresses[index])) return false;
  const elementSizes = [1, 4, 1, 1, 1];
  if (tableSlices.some((slice, index) => {
    const size = sliceByteSize(slice, elementSizes[index]!);
    return size == null || !image.isMappedRange(slice.address, size);
  })) return false;
  if (functionTable.address !== pclnTable.address) return false;
  if (functionTable.length !== header.functionCount + 1) return false;
  const fieldSize = header.layout.functabFieldSize(image.pointerSize);
  return image.isMappedRange(functionTable.address, header.functionCount * fieldSize * 2 + fieldSize);
};

const tableHasBoundedGap = (
  slice: GoSlice,
  elementSize: number,
  nextAddress: bigint,
  pointerSize: 4 | 8
): boolean => {
  const byteSize = sliceByteSize(slice, elementSize);
  if (byteSize == null) return false;
  const end = slice.address + BigInt(byteSize);
  return end <= nextAddress && nextAddress - end < BigInt(pointerSize);
};

const validateTableBoundaries = (
  header: PcHeader,
  moduleData: ModuleDataPrefix,
  pointerSize: 4 | 8
): boolean => {
  const [functionNames, compilationUnits, files, pcTable] = moduleData.slices;
  const addresses = header.tableOffsets.map(offset => header.address + offset);
  return !!functionNames && !!compilationUnits && !!files && !!pcTable &&
    tableHasBoundedGap(functionNames, 1, addresses[1]!, pointerSize) &&
    tableHasBoundedGap(compilationUnits, 4, addresses[2]!, pointerSize) &&
    tableHasBoundedGap(files, 1, addresses[3]!, pointerSize) &&
    tableHasBoundedGap(pcTable, 1, addresses[4]!, pointerSize);
};

const validateRanges = (
  image: GoRuntimeAddressSpace,
  header: PcHeader,
  moduleData: ModuleDataPrefix,
  functions: GoRuntimeFunction[]
): boolean => {
  const first = functions[0];
  const last = functions.at(-1);
  if (!first || !last || moduleData.text >= moduleData.textEnd) return false;
  if (moduleData.minPc !== first.start || moduleData.maxPc !== last.end) return false;
  if (moduleData.minPc < moduleData.text || moduleData.maxPc > moduleData.textEnd) return false;
  if (!image.isExecutableRange(moduleData.text, moduleData.textEnd)) return false;
  const textBytes = moduleData.maxPc - moduleData.minPc;
  if (textBytes <= 0n || textBytes > BigInt(Number.MAX_SAFE_INTEGER)) return false;
  // runtime.findfuncbucket is 20 bytes per 4096-byte text bucket.
  // https://github.com/golang/go/blob/go1.26.4/src/runtime/symtab.go
  const lookupSize = Math.ceil(Number(textBytes) / 4096) * 20;
  if (!image.isMappedRange(moduleData.findFuncTable, lookupSize)) return false;
  return header.textField == null || header.textField === 0n || header.textField === moduleData.text;
};

export const parseGoRuntimeMetadata = async (
  image: GoRuntimeAddressSpace,
  pcHeaderAddress: bigint,
  moduleDataAddress: bigint
): Promise<GoRuntimeMetadata | null> => {
  const header = await parseGoPcHeader(image, pcHeaderAddress);
  if (!header) return null;
  return parseGoRuntimeMetadataFromHeader(image, header, moduleDataAddress);
};

export const parseGoRuntimeMetadataFromHeader = async (
  image: GoRuntimeAddressSpace,
  header: PcHeader,
  moduleDataAddress: bigint
): Promise<GoRuntimeMetadata | null> => {
  const moduleData = await parseModuleDataPrefix(image, moduleDataAddress, header.address);
  if (!moduleData || !validateSlices(image, header, moduleData)) return null;
  if (!validateTableBoundaries(header, moduleData, image.pointerSize)) return null;
  if (!(await validateGoFileTables(image, header, moduleData))) return null;
  const functions = await parseGoFunctions(image, header, moduleData);
  if (!functions || !validateRanges(image, header, moduleData, functions)) return null;
  return {
    layout: header.layout.id,
    pointerSize: image.pointerSize,
    pcHeaderAddress: header.address,
    moduleDataAddress,
    fileCount: header.fileCount,
    textRange: { start: moduleData.text, end: moduleData.textEnd },
    functions
  };
};
