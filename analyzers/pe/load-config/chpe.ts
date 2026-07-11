"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import {
  addReferenceMessage,
  PE32_POINTER_BYTES,
  readMappedReferenceTable,
  readMappedReferenceView,
  referencePointerRva,
  type PeRvaMapping,
  type PePointerBytes,
} from "./reference-reader.js";
import type {
  PeChpeArm64EcMetadata,
  PeChpeCodeMapEntry,
  PeChpeEntryPointRange,
  PeChpeMetadata,
  PeChpeRedirection,
  PeChpeX86Metadata
} from "./reference-types.js";
import { parseChpeRuntimeFunctions } from "./chpe-runtime-functions.js";

// LLVM's upstream COFF definitions provide the ARM64EC metadata fields, entry
// layouts, v2 extension, and low-bit range type encoding used below.
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/Object/COFF.h
const ARM64EC_V1_SIZE = 80;
const ARM64EC_V2_SIZE = 92;
const ARM64EC_OFFSETS = {
  version: 0, codeMap: 4, codeMapCount: 8, codeRangesToEntryPoints: 12,
  redirectionMetadata: 16, dispatchCallNoRedirect: 20, dispatchRet: 24,
  dispatchCall: 28, dispatchIcall: 32, dispatchIcallCfg: 36, alternateEntryPoint: 40,
  auxiliaryIat: 44, codeRangesToEntryPointsCount: 48, redirectionMetadataCount: 52,
  getX64Information: 56, setX64Information: 60, extraRfeTable: 64, extraRfeTableSize: 68,
  dispatchFptr: 72, auxiliaryIatCopy: 76, auxiliaryDelayloadIat: 80,
  auxiliaryDelayloadIatCopy: 84, hybridImageInfoBitfield: 88
} as const;
const ARM64EC_RANGE_ENTRY_SIZE = 8;
const ARM64EC_ENTRY_POINT_RANGE_SIZE = 12;
const ARM64EC_REDIRECTION_ENTRY_SIZE = 8;
const ARM64EC_RANGE_TYPE_MASK = 3;

// System Informer ntimage.h IMAGE_CHPE_METADATA_X86 defines the v1-v3 fields
// and IMAGE_CHPE_RANGE_ENTRY defines the low NativeCode bit.
// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntimage.h
const X86_V1_SIZE = 40;
const X86_V2_SIZE = 44;
const X86_V3_SIZE = 48;
const X86_OFFSETS = {
  version: 0, codeMap: 4, codeMapCount: 8, exceptionHandler: 12, dispatchCall: 16,
  dispatchIndirectCall: 20, dispatchIndirectCallCfg: 24, dispatchRet: 28,
  dispatchRetLeaf: 32, dispatchJump: 36, compilerIat: 40, rdtsc: 44
} as const;
const X86_RANGE_ENTRY_SIZE = 8;
const X86_NATIVE_CODE_MASK = 1;

const chpeRangeKind = (value: number): PeChpeCodeMapEntry["kind"] => {
  if (value === 0) return "ARM64";
  if (value === 1) return "ARM64EC";
  if (value === 2) return "AMD64";
  return "UNKNOWN";
};

const readArm64EcCodeMap = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  rva: number,
  count: number
): Promise<PeChpeCodeMapEntry[]> => {
  const view = await readMappedReferenceTable(
    reader, mapping, warnings, notes, "CHPE CodeMap", rva, count, ARM64EC_RANGE_ENTRY_SIZE
  );
  if (!view) return [];
  return Array.from({ length: count }, (_, index) => {
    const offset = index * ARM64EC_RANGE_ENTRY_SIZE;
    const startWithKind = view.getUint32(offset, true);
    return {
      startRva: startWithKind & ~ARM64EC_RANGE_TYPE_MASK,
      length: view.getUint32(offset + 4, true),
      kind: chpeRangeKind(startWithKind & ARM64EC_RANGE_TYPE_MASK)
    };
  });
};

const readX86CodeMap = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  rva: number,
  count: number
): Promise<PeChpeCodeMapEntry[]> => {
  const view = await readMappedReferenceTable(
    reader, mapping, warnings, notes, "CHPE x86 CodeMap", rva, count, X86_RANGE_ENTRY_SIZE
  );
  if (!view) return [];
  return Array.from({ length: count }, (_, index) => {
    const offset = index * X86_RANGE_ENTRY_SIZE;
    const startWithNativeBit = view.getUint32(offset, true);
    return {
      startRva: startWithNativeBit & ~X86_NATIVE_CODE_MASK,
      length: view.getUint32(offset + 4, true),
      kind: startWithNativeBit & X86_NATIVE_CODE_MASK ? "ARM64" : "X86"
    };
  });
};

const readEntryPointRanges = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  rva: number,
  count: number
): Promise<PeChpeEntryPointRange[]> => {
  const view = await readMappedReferenceTable(
    reader, mapping, warnings, notes, "CHPE entry point ranges",
    rva, count, ARM64EC_ENTRY_POINT_RANGE_SIZE
  );
  if (!view) return [];
  return Array.from({ length: count }, (_, index) => {
    const offset = index * ARM64EC_ENTRY_POINT_RANGE_SIZE;
    return {
      startRva: view.getUint32(offset, true),
      endRva: view.getUint32(offset + 4, true),
      entryPointRva: view.getUint32(offset + 8, true)
    };
  });
};

const readRedirections = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  rva: number,
  count: number
): Promise<PeChpeRedirection[]> => {
  const view = await readMappedReferenceTable(
    reader, mapping, warnings, notes, "CHPE redirections",
    rva, count, ARM64EC_REDIRECTION_ENTRY_SIZE
  );
  if (!view) return [];
  return Array.from({ length: count }, (_, index) => {
    const offset = index * ARM64EC_REDIRECTION_ENTRY_SIZE;
    return { sourceRva: view.getUint32(offset, true), destinationRva: view.getUint32(offset + 4, true) };
  });
};

const readArm64EcHeader = (view: DataView, rva: number): PeChpeArm64EcMetadata => ({
  kind: "arm64ec",
  rva,
  version: view.getUint32(ARM64EC_OFFSETS.version, true),
  codeMapRva: view.getUint32(ARM64EC_OFFSETS.codeMap, true),
  codeMapCount: view.getUint32(ARM64EC_OFFSETS.codeMapCount, true),
  codeRangesToEntryPointsRva: view.getUint32(ARM64EC_OFFSETS.codeRangesToEntryPoints, true),
  redirectionMetadataRva: view.getUint32(ARM64EC_OFFSETS.redirectionMetadata, true),
  osArm64xDispatchCallNoRedirectRva: view.getUint32(ARM64EC_OFFSETS.dispatchCallNoRedirect, true),
  osArm64xDispatchRetRva: view.getUint32(ARM64EC_OFFSETS.dispatchRet, true),
  osArm64xDispatchCallRva: view.getUint32(ARM64EC_OFFSETS.dispatchCall, true),
  osArm64xDispatchIcallRva: view.getUint32(ARM64EC_OFFSETS.dispatchIcall, true),
  osArm64xDispatchIcallCfgRva: view.getUint32(ARM64EC_OFFSETS.dispatchIcallCfg, true),
  alternateEntryPointRva: view.getUint32(ARM64EC_OFFSETS.alternateEntryPoint, true),
  auxiliaryIatRva: view.getUint32(ARM64EC_OFFSETS.auxiliaryIat, true),
  codeRangesToEntryPointsCount: view.getUint32(ARM64EC_OFFSETS.codeRangesToEntryPointsCount, true),
  redirectionMetadataCount: view.getUint32(ARM64EC_OFFSETS.redirectionMetadataCount, true),
  getX64InformationFunctionPointerRva: view.getUint32(ARM64EC_OFFSETS.getX64Information, true),
  setX64InformationFunctionPointerRva: view.getUint32(ARM64EC_OFFSETS.setX64Information, true),
  extraRfeTableRva: view.getUint32(ARM64EC_OFFSETS.extraRfeTable, true),
  extraRfeTableSize: view.getUint32(ARM64EC_OFFSETS.extraRfeTableSize, true),
  osArm64xDispatchFptrRva: view.getUint32(ARM64EC_OFFSETS.dispatchFptr, true),
  auxiliaryIatCopyRva: view.getUint32(ARM64EC_OFFSETS.auxiliaryIatCopy, true),
  codeMap: [], entryPointRanges: [], redirections: [], extraRfeEntries: []
});

const addArm64EcV2Fields = (metadata: PeChpeArm64EcMetadata, view: DataView): void => {
  metadata.auxiliaryDelayloadIatRva = view.getUint32(ARM64EC_OFFSETS.auxiliaryDelayloadIat, true);
  metadata.auxiliaryDelayloadIatCopyRva = view.getUint32(ARM64EC_OFFSETS.auxiliaryDelayloadIatCopy, true);
  metadata.hybridImageInfoBitfield = view.getUint32(ARM64EC_OFFSETS.hybridImageInfoBitfield, true);
};

const parseArm64EcMetadata = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  rva: number
): Promise<PeChpeArm64EcMetadata | null> => {
  const initialView = await readMappedReferenceView(
    reader, mapping, warnings, notes, "CHPE ARM64EC metadata", rva, ARM64EC_V1_SIZE
  );
  if (!initialView) return null;
  const metadata = readArm64EcHeader(initialView, rva);
  if (metadata.version >= 2) {
    const v2View = await readMappedReferenceView(
      reader, mapping, warnings, notes, "CHPE ARM64EC v2 metadata", rva, ARM64EC_V2_SIZE
    );
    if (v2View) addArm64EcV2Fields(metadata, v2View);
  }
  if (metadata.version > 2) {
    addReferenceMessage(notes, `LOAD_CONFIG: CHPE ARM64EC v${metadata.version} parsed using the known v2 prefix.`);
  }
  [
    metadata.codeMap,
    metadata.entryPointRanges,
    metadata.redirections,
    metadata.extraRfeEntries
  ] = await Promise.all([
    readArm64EcCodeMap(reader, mapping, warnings, notes, metadata.codeMapRva, metadata.codeMapCount),
    readEntryPointRanges(reader, mapping, warnings, notes, metadata.codeRangesToEntryPointsRva,
      metadata.codeRangesToEntryPointsCount),
    readRedirections(reader, mapping, warnings, notes, metadata.redirectionMetadataRva,
      metadata.redirectionMetadataCount),
    parseChpeRuntimeFunctions(
      reader, mapping, warnings, notes, metadata.extraRfeTableRva, metadata.extraRfeTableSize
    )
  ]);
  return metadata;
};

const x86MetadataSize = (version: number): number =>
  version >= 3 ? X86_V3_SIZE : version >= 2 ? X86_V2_SIZE : X86_V1_SIZE;

const readX86Header = (view: DataView, rva: number, version: number): PeChpeX86Metadata => ({
  kind: "x86",
  rva,
  version,
  codeMapRva: view.getUint32(X86_OFFSETS.codeMap, true),
  codeMapCount: view.getUint32(X86_OFFSETS.codeMapCount, true),
  wowA64ExceptionHandlerRva: view.getUint32(X86_OFFSETS.exceptionHandler, true),
  wowA64DispatchCallRva: view.getUint32(X86_OFFSETS.dispatchCall, true),
  wowA64DispatchIndirectCallRva: view.getUint32(X86_OFFSETS.dispatchIndirectCall, true),
  wowA64DispatchIndirectCallCfgRva: view.getUint32(X86_OFFSETS.dispatchIndirectCallCfg, true),
  wowA64DispatchRetRva: view.getUint32(X86_OFFSETS.dispatchRet, true),
  wowA64DispatchRetLeafRva: view.getUint32(X86_OFFSETS.dispatchRetLeaf, true),
  wowA64DispatchJumpRva: view.getUint32(X86_OFFSETS.dispatchJump, true),
  ...(version >= 2 ? { compilerIatRva: view.getUint32(X86_OFFSETS.compilerIat, true) } : {}),
  ...(version >= 3 ? { wowA64RdtscRva: view.getUint32(X86_OFFSETS.rdtsc, true) } : {}),
  codeMap: []
});

const parseX86Metadata = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  rva: number
): Promise<PeChpeX86Metadata | null> => {
  const initialView = await readMappedReferenceView(
    reader, mapping, warnings, notes, "CHPE x86 metadata", rva, X86_V1_SIZE
  );
  if (!initialView) return null;
  const version = initialView.getUint32(X86_OFFSETS.version, true);
  const view = version < 2 ? initialView : await readMappedReferenceView(
    reader, mapping, warnings, notes, `CHPE x86 v${version} metadata`, rva, x86MetadataSize(version)
  );
  if (!view) return null;
  const metadata = readX86Header(view, rva, version);
  if (version > 3) addReferenceMessage(notes, `LOAD_CONFIG: CHPE x86 v${version} parsed using the known v3 prefix.`);
  metadata.codeMap = await readX86CodeMap(
    reader, mapping, warnings, notes, metadata.codeMapRva, metadata.codeMapCount
  );
  return metadata;
};

export const parseChpeMetadata = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  imageBase: bigint,
  pointerBytes: PePointerBytes,
  warnings: string[],
  notes: string[],
  pointerVa: bigint
): Promise<PeChpeMetadata | null> => {
  const rva = referencePointerRva(imageBase, warnings, "CHPEMetadataPointer", pointerVa);
  if (rva == null) return null;
  return pointerBytes === PE32_POINTER_BYTES
    ? parseX86Metadata(reader, mapping, warnings, notes, rva)
    : parseArm64EcMetadata(reader, mapping, warnings, notes, rva);
};
