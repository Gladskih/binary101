"use strict";

import { readExact, readWord, toView } from "./memory.js";
import type { GoRuntimeAddressSpace, GoRuntimeFunction } from "./types.js";
import type { GoSlice, ModuleDataPrefix, PcHeader } from "./parser.js";
import { GO_RUNTIME_MAX_TABLE_BYTE_LENGTH } from "./limits.js";

const textDecoder = new TextDecoder("utf-8", { fatal: true });

const sliceByteSize = (slice: GoSlice, elementSize: number): number | null => {
  const size = slice.length * elementSize;
  return Number.isSafeInteger(size) && size <= GO_RUNTIME_MAX_TABLE_BYTE_LENGTH ? size : null;
};

const nullTerminator = (bytes: Uint8Array, offset: number): number | null => {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= bytes.byteLength) return null;
  const end = bytes.indexOf(0, offset);
  // A defensive 4 KiB ceiling keeps a missing NUL from turning one name into a huge decode.
  return end > offset && end - offset <= 4096 ? end : null;
};

const decodeNullTerminated = (
  bytes: Uint8Array,
  offset: number
): { text: string; end: number } | null => {
  const end = nullTerminator(bytes, offset);
  if (end == null) return null;
  try {
    return { text: textDecoder.decode(bytes.subarray(offset, end)), end };
  } catch {
    return null;
  }
};

const isAlignmentPadding = (bytes: Uint8Array, offset: number, pointerSize: 4 | 8): boolean =>
  bytes.byteLength - offset < pointerSize && bytes.subarray(offset).every(value => value === 0);

const collectStringStarts = (
  bytes: Uint8Array,
  pointerSize: 4 | 8
): Set<number> | null => {
  const starts = new Set<number>();
  let offset = 0;
  while (offset < bytes.byteLength) {
    if (isAlignmentPadding(bytes, offset, pointerSize)) return starts;
    const decoded = decodeNullTerminated(bytes, offset);
    if (!decoded) return null;
    starts.add(offset);
    offset = decoded.end + 1;
  }
  return offset === bytes.byteLength ? starts : null;
};

export const validateGoFileTables = async (
  image: GoRuntimeAddressSpace,
  header: PcHeader,
  moduleData: ModuleDataPrefix
): Promise<boolean> => {
  const compilationUnits = moduleData.slices[1];
  const files = moduleData.slices[2];
  if (!compilationUnits || !files) return false;
  const fileBytes = await readExact(image, files.address, files.length);
  const cuSize = sliceByteSize(compilationUnits, 4);
  const cuBytes = cuSize == null ? null : await readExact(image, compilationUnits.address, cuSize);
  if (!fileBytes || !cuBytes) return false;
  const starts = collectStringStarts(fileBytes, image.pointerSize);
  if (!starts || starts.size !== header.fileCount) return false;
  const view = toView(cuBytes);
  // cmd/link writes ^uint32(0) for dead-code-eliminated file entries:
  // https://github.com/golang/go/blob/go1.26.4/src/cmd/link/internal/ld/pcln.go
  for (let offset = 0; offset < view.byteLength; offset += 4) {
    const fileOffset = view.getUint32(offset, true);
    if (fileOffset !== 0xffff_ffff && !starts.has(fileOffset)) return false;
  }
  return true;
};

const readFunctionEntry = (
  view: DataView,
  offset: number,
  fieldSize: number
): bigint => fieldSize === 8
  ? view.getBigUint64(offset, true)
  : BigInt(view.getUint32(offset, true));

const functionAddress = (header: PcHeader, text: bigint, value: bigint): bigint =>
  header.layout.relativeFunctionEntries ? text + value : value;

export const parseGoFunctions = async (
  image: GoRuntimeAddressSpace,
  header: PcHeader,
  moduleData: ModuleDataPrefix
): Promise<GoRuntimeFunction[] | null> => {
  const functionNames = moduleData.slices[0];
  const pclnTable = moduleData.slices[4];
  if (!functionNames || !pclnTable) return null;
  const names = await readExact(image, functionNames.address, functionNames.length);
  if (!names) return null;
  const fieldSize = header.layout.functabFieldSize(image.pointerSize);
  const tableSize = header.functionCount * fieldSize * 2 + fieldSize;
  const table = await readExact(image, pclnTable.address, tableSize);
  if (!table) return null;
  return parseGoFunctionRows(image, header, moduleData, names, toView(table), fieldSize);
};

const parseGoFunctionRows = async (
  image: GoRuntimeAddressSpace,
  header: PcHeader,
  moduleData: ModuleDataPrefix,
  names: Uint8Array,
  table: DataView,
  fieldSize: number
): Promise<GoRuntimeFunction[] | null> => {
  const pclnTable = moduleData.slices[4];
  if (!pclnTable) return null;
  const functions: GoRuntimeFunction[] = [];
  for (let index = 0; index < header.functionCount; index += 1) {
    const pairOffset = index * fieldSize * 2;
    const entryValue = readFunctionEntry(table, pairOffset, fieldSize);
    const nextValue = readFunctionEntry(table, pairOffset + fieldSize * 2, fieldSize);
    const functionOffset = readFunctionEntry(table, pairOffset + fieldSize, fieldSize);
    const start = functionAddress(header, moduleData.text, entryValue);
    const end = functionAddress(header, moduleData.text, nextValue);
    if (start >= end || functionOffset > BigInt(pclnTable.length - 8)) return null;
    const namePosition = header.layout.relativeFunctionEntries ? 4 : image.pointerSize;
    const metadata = await readExact(image, pclnTable.address + functionOffset, namePosition + 4);
    if (!metadata) return null;
    const metadataView = toView(metadata);
    const metadataEntry = header.layout.relativeFunctionEntries
      ? BigInt(metadataView.getUint32(0, true))
      : readWord(metadataView, 0, image.pointerSize);
    const name = decodeNullTerminated(names, metadataView.getInt32(namePosition, true))?.text;
    if (metadataEntry !== entryValue || name == null) return null;
    if (!image.isExecutableRange(start, end)) return null;
    functions.push({ name, start, end });
  }
  return functions;
};
