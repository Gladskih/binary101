import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface LegacyCodeViewModule {
  kind: "module"; name: string; library: number; overlay: number; style: string;
  version?: number;
  segments: { segment: number; offset: number; size: number }[];
}
export interface LegacyCodeViewLibraries { kind: "libraries"; names: string[]; }
export interface LegacyCodeViewSegmentNames { kind: "segmentNames"; names: { offset: number; name: string }[]; }
export interface LegacyCodeViewSegmentMap {
  kind: "segmentMap"; logicalCount: number;
  segments: { flags: number; overlay: number; group: number; frame: number;
    name: number; className: number; offset: number; size: number }[];
}
export interface LegacyCodeViewFiles { kind: "files"; names: string[]; modules: { first: number; count: number }[]; }

// OMFModule, OMFSegMap, libraries and file index as consumed by Microsoft cvdump.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/cvdump.cpp#L394
// https://github.com/open-watcom/open-watcom-v2/blob/master/bld/watcom/h/cv4.h
export const readLegacyCodeViewModule = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewModule> => {
  const header = await reader.view(0, 8);
  const count = header.getUint16(4, true);
  if (count * 12 > reader.size - 8) throw new Error("CodeView module segment array is truncated.");
  const segments: LegacyCodeViewModule["segments"] = [];
  for (let index = 0; index < count; index++) {
    const view = await reader.view(8 + index * 12, 12);
    if (view.getUint16(2, true)) reader.warn("CodeView module segment reserved field is nonzero.");
    segments.push({ segment: view.getUint16(0, true), offset: view.getUint32(4, true), size: view.getUint32(8, true) });
  }
  return { kind: "module", name: (await reader.pascal(8 + count * 12)).name,
    overlay: header.getUint16(0, true), library: header.getUint16(2, true),
    style: String.fromCharCode(header.getUint8(6), header.getUint8(7)), segments };
};

export const readLegacyCodeViewLibraries = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewLibraries> => {
  const names: string[] = [];
  let offset = 0;
  while (offset < reader.size) {
    const value = await reader.pascal(offset);
    names.push(value.name);
    offset = value.end;
  }
  return { kind: "libraries", names };
};

export const readLegacyCodeViewSegmentNames = async (
  reader: LegacyCodeViewReader
): Promise<LegacyCodeViewSegmentNames> => {
  const names: LegacyCodeViewSegmentNames["names"] = [];
  let offset = 0;
  while (offset < reader.size) {
    const value = await reader.ansi(offset);
    names.push({ offset, name: value.name });
    offset = value.end;
  }
  return { kind: "segmentNames", names };
};

export const readLegacyCodeViewSegmentMap = async (
  reader: LegacyCodeViewReader
): Promise<LegacyCodeViewSegmentMap> => {
  const header = await reader.view(0, 4);
  const count = header.getUint16(0, true);
  if (count * 20 > reader.size - 4) throw new Error("CodeView segment map is truncated.");
  const segments: LegacyCodeViewSegmentMap["segments"] = [];
  for (let index = 0; index < count; index++) {
    const view = await reader.view(4 + index * 20, 20);
    segments.push({ flags: view.getUint16(0, true), overlay: view.getUint16(2, true),
      group: view.getUint16(4, true), frame: view.getUint16(6, true), name: view.getUint16(8, true),
      className: view.getUint16(10, true), offset: view.getUint32(12, true), size: view.getUint32(16, true) });
  }
  if (header.getUint16(2, true) > count) reader.warn("CodeView logical segment count exceeds total segments.");
  return { kind: "segmentMap", logicalCount: header.getUint16(2, true), segments };
};

export const readLegacyCodeViewFiles = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewFiles> => {
  const header = await reader.view(0, 4);
  const moduleCount = header.getUint16(0, true);
  const referenceCount = header.getUint16(2, true);
  const namesOffset = 4 + moduleCount * 4 + referenceCount * 4;
  if (namesOffset > reader.size) throw new Error("CodeView file index arrays are truncated.");
  const modules: LegacyCodeViewFiles["modules"] = [];
  const names = new Map<number, string>();
  const references: string[] = [];
  for (let index = 0; index < referenceCount; index++) {
    const offset = await reader.uint32(4 + moduleCount * 4 + index * 4);
    let name = names.get(offset);
    if (name == null) { name = (await reader.pascal(namesOffset + offset)).name; names.set(offset, name); }
    references.push(name);
  }
  for (let index = 0; index < moduleCount; index++) {
    const first = await reader.uint16(4 + index * 2);
    const count = await reader.uint16(4 + moduleCount * 2 + index * 2);
    if (first + count > referenceCount) throw new Error("CodeView file index references exceed its name array.");
    modules.push({ first, count });
  }
  return { kind: "files", names: references, modules };
};
