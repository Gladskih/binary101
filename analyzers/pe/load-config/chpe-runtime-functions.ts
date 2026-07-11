"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import {
  addReferenceMessage,
  readMappedReferenceTable,
  type PeRvaMapping
} from "./reference-reader.js";
import type { PeArm64RuntimeFunctionEntry } from "./reference-types.js";

// Microsoft ARM64 exception handling, ".pdata records" and "Packed unwind data".
// https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170
const ENTRY_SIZE = 8;
const PACKED_LAYOUT = {
  flagMask: 0b11,
  functionLengthMask: 0x7ff,
  savedFpRegisterMask: 0b111,
  savedIntegerRegisterMask: 0xf,
  homesIntegerParametersMask: 1,
  chainReturnMask: 0b11,
  frameSizeMask: 0x1ff
} as const;

type PeArm64ChainReturn = "unchained" | "saves-lr" | "chained-pac" | "chained";

const chainReturn = (
  value: number
): PeArm64ChainReturn => {
  if (value === 0) return "unchained";
  if (value === 1) return "saves-lr";
  if (value === 2) return "chained-pac";
  return "chained";
};

const decodeEntry = (view: DataView, offset: number): PeArm64RuntimeFunctionEntry => {
  const beginRva = view.getUint32(offset, true);
  const unwindData = view.getUint32(offset + Uint32Array.BYTES_PER_ELEMENT, true);
  const flag = unwindData & PACKED_LAYOUT.flagMask;
  if (flag === 0) return { beginRva, unwindKind: "exception", exceptionInformationRva: unwindData };
  // Microsoft reserves Flag=3, while current MSVC dumpbin labels emitted values as chained pdata.
  // Preserve that established project interpretation and expose the referenced entry RVA.
  if (flag === 3) return { beginRva, unwindKind: "chained", targetPdataRva: unwindData & ~3 };
  return {
    beginRva,
    unwindKind: flag === 1 ? "packed" : "packed-fragment",
    functionLengthBytes: ((unwindData >>> 2) & PACKED_LAYOUT.functionLengthMask) * 4,
    savedFpRegisterField: (unwindData >>> 13) & PACKED_LAYOUT.savedFpRegisterMask,
    savedIntegerRegisterCount: (unwindData >>> 16) & PACKED_LAYOUT.savedIntegerRegisterMask,
    homesIntegerParameters: ((unwindData >>> 20) & PACKED_LAYOUT.homesIntegerParametersMask) !== 0,
    chainReturn: chainReturn((unwindData >>> 21) & PACKED_LAYOUT.chainReturnMask),
    frameSizeBytes: ((unwindData >>> 23) & PACKED_LAYOUT.frameSizeMask) * 16
  };
};

export const parseChpeRuntimeFunctions = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  tableRva: number,
  byteSize: number
): Promise<PeArm64RuntimeFunctionEntry[]> => {
  if (byteSize % ENTRY_SIZE !== 0) {
    addReferenceMessage(warnings,
      `LOAD_CONFIG: CHPE ExtraRFETableSize ${byteSize} is not divisible by ${ENTRY_SIZE}.`);
  }
  const count = Math.floor(byteSize / ENTRY_SIZE);
  const view = await readMappedReferenceTable(
    reader, mapping, warnings, notes, "CHPE ExtraRFETable", tableRva, count, ENTRY_SIZE
  );
  if (!view) return [];
  return Array.from({ length: count }, (_, index) => decodeEntry(view, index * ENTRY_SIZE));
};
