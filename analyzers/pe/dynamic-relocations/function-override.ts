"use strict";

// Windows SDK winnt.h: IMAGE_FUNCTION_OVERRIDE_HEADER, IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION,
// IMAGE_BDD_INFO, IMAGE_BDD_DYNAMIC_RELOCATION and IMAGE_BASE_RELOCATION.
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
const DWORD_SIZE = 4;
const OVERRIDE_HEADER_SIZE = 16;
const BASE_RELOCATION_HEADER_SIZE = 8;
const BDD_HEADER_SIZE = 8;
const BDD_NODE_SIZE = 8;

export type PeFunctionOverrideRelocation = { pageRva: number; typeOffsets: number[] };
export type PeFunctionOverrideRecord = {
  originalRva: number;
  bddOffset: number;
  overridingRvas: number[];
  baseRelocations: PeFunctionOverrideRelocation[];
};
export type PeFunctionOverrideBdd = {
  offset: number;
  version: number;
  nodes: Array<{ left: number; right: number; value: number }>;
};
export type PeFunctionOverride = {
  functions: PeFunctionOverrideRecord[];
  bddInfos: PeFunctionOverrideBdd[];
};

const parseRelocationBlocks = (
  view: DataView,
  start: number,
  end: number,
  warnings: string[]
): PeFunctionOverrideRelocation[] | null => {
  const blocks: PeFunctionOverrideRelocation[] = [];
  let cursor = start;
  while (cursor < end) {
    if (end - cursor < BASE_RELOCATION_HEADER_SIZE) {
      warnings.push("FunctionOverride: truncated base relocation block header.");
      return null;
    }
    const size = view.getUint32(cursor + DWORD_SIZE, true);
    if (size < BASE_RELOCATION_HEADER_SIZE || size > end - cursor || size % 2 !== 0) {
      warnings.push("FunctionOverride: invalid base relocation block size.");
      return null;
    }
    const typeOffsets: number[] = [];
    for (let offset = cursor + BASE_RELOCATION_HEADER_SIZE; offset < cursor + size; offset += 2) {
      typeOffsets.push(view.getUint16(offset, true));
    }
    blocks.push({ pageRva: view.getUint32(cursor, true), typeOffsets });
    cursor += size;
  }
  return blocks;
};

const parseFunctionRecord = (
  view: DataView,
  start: number,
  end: number,
  warnings: string[]
): { record: PeFunctionOverrideRecord; next: number } | null => {
  if (end - start < OVERRIDE_HEADER_SIZE) {
    warnings.push("FunctionOverride: truncated function record header.");
    return null;
  }
  const rvaSize = view.getUint32(start + 8, true);
  const relocSize = view.getUint32(start + 12, true);
  if (rvaSize % DWORD_SIZE !== 0 || rvaSize > end - start - OVERRIDE_HEADER_SIZE) {
    warnings.push("FunctionOverride: invalid or truncated RVA array.");
    return null;
  }
  const relocStart = start + OVERRIDE_HEADER_SIZE + rvaSize;
  if (relocSize > end - relocStart) {
    warnings.push("FunctionOverride: truncated base relocation region.");
    return null;
  }
  const baseRelocations = parseRelocationBlocks(view, relocStart, relocStart + relocSize, warnings);
  if (!baseRelocations) return null;
  const overridingRvas: number[] = [];
  for (let offset = start + OVERRIDE_HEADER_SIZE; offset < relocStart; offset += DWORD_SIZE) {
    overridingRvas.push(view.getUint32(offset, true));
  }
  return {
    record: {
      originalRva: view.getUint32(start, true),
      bddOffset: view.getUint32(start + DWORD_SIZE, true),
      overridingRvas,
      baseRelocations
    },
    next: relocStart + relocSize
  };
};

const parseFunctionRecords = (
  view: DataView,
  start: number,
  end: number,
  warnings: string[]
): PeFunctionOverrideRecord[] => {
  const functions: PeFunctionOverrideRecord[] = [];
  let cursor = start;
  while (cursor < end) {
    const parsed = parseFunctionRecord(view, cursor, end, warnings);
    if (!parsed) break;
    functions.push(parsed.record);
    cursor = parsed.next;
  }
  return functions;
};

const parseBddInfos = (
  view: DataView,
  start: number,
  end: number,
  warnings: string[]
): PeFunctionOverrideBdd[] => {
  const bddInfos: PeFunctionOverrideBdd[] = [];
  let cursor = start;
  while (cursor < end) {
    if (end - cursor < BDD_HEADER_SIZE) {
      warnings.push("FunctionOverride: truncated BDD header.");
      break;
    }
    const version = view.getUint32(cursor, true);
    const size = view.getUint32(cursor + DWORD_SIZE, true);
    if (size > end - cursor - BDD_HEADER_SIZE) {
      warnings.push("FunctionOverride: truncated BDD payload.");
      break;
    }
    if (version === 1 && size % BDD_NODE_SIZE !== 0) {
      warnings.push("FunctionOverride: BDD version 1 has an incomplete node.");
      break;
    }
    const nodes: PeFunctionOverrideBdd["nodes"] = [];
    if (version === 1) {
      for (let offset = cursor + BDD_HEADER_SIZE; offset < cursor + BDD_HEADER_SIZE + size;
        offset += BDD_NODE_SIZE) {
        nodes.push({ left: view.getUint16(offset, true), right: view.getUint16(offset + 2, true),
          value: view.getUint32(offset + DWORD_SIZE, true) });
      }
    } else {
      warnings.push(`FunctionOverride: unsupported BDD version ${version}.`);
    }
    bddInfos.push({ offset: cursor - start, version, nodes });
    cursor += BDD_HEADER_SIZE + size;
  }
  return bddInfos;
};

export const parseFunctionOverride = (
  view: DataView,
  start: number,
  end: number,
  warnings: string[]
): PeFunctionOverride | null => {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 ||
    end > view.byteLength || end - start < DWORD_SIZE) {
    warnings.push("FunctionOverride: truncated fixup header.");
    return null;
  }
  const functionRegionSize = view.getUint32(start, true);
  if (functionRegionSize > end - start - DWORD_SIZE) {
    warnings.push("FunctionOverride: FuncOverrideSize exceeds the fixup payload.");
    return null;
  }
  const bddStart = start + DWORD_SIZE + functionRegionSize;
  const functions = parseFunctionRecords(view, start + DWORD_SIZE, bddStart, warnings);
  const bddInfos = parseBddInfos(view, bddStart, end, warnings);
  const bddOffsets = new Set(bddInfos.map(info => info.offset));
  return {
    functions: functions.filter(record => {
      if (bddOffsets.has(record.bddOffset)) return true;
      warnings.push(`FunctionOverride: BDDOffset 0x${record.bddOffset.toString(16)} is invalid.`);
      return false;
    }),
    bddInfos
  };
};
