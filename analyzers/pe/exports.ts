"use strict";

import type { AddCoverageRegion, PeDataDirectory, RvaToOffset } from "./types.js";

export async function parseExportDirectory(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<{
  flags: number;
  timestamp: number;
  version: number;
  dllName: string;
  Base: number;
  NumberOfFunctions: number;
  NumberOfNames: number;
  namePointerTable: number;
  ordinalTable: number;
  entries: Array<{ ordinal: number; rva: number; name: string | null; forwarder?: string | null }>;
  issues: string[];
} | null> {
  const dir = dataDirs.find(d => d.name === "EXPORT");
  if (!dir?.rva) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  const availableDirSize = Math.max(0, Math.min(dir.size, file.size - base));
  addCoverageRegion("EXPORT directory", base, availableDirSize);
  if (availableDirSize < 40) {
    return {
      flags: 0,
      timestamp: 0,
      version: 0,
      dllName: "",
      Base: 0,
      NumberOfFunctions: 0,
      NumberOfNames: 0,
      namePointerTable: 0,
      ordinalTable: 0,
      entries: [],
      issues: ["Export directory is smaller than the 40-byte IMAGE_EXPORT_DIRECTORY header."]
    };
  }
  const dv = new DataView(await file.slice(base, base + 40).arrayBuffer());
  const isReadableOffset = (offset: number | null): offset is number =>
    offset != null && offset >= 0 && offset < file.size;
  const readStr = async (offset: number): Promise<{ text: string; truncated: boolean }> => {
    if (offset < 0 || offset >= file.size) return { text: "", truncated: false };
    let text = "";
    let pos = offset;
    while (pos < file.size) {
      const chunk = new Uint8Array(await file.slice(pos, pos + 64).arrayBuffer());
      if (chunk.byteLength === 0) return { text, truncated: true };
      const zeroIndex = chunk.indexOf(0);
      if (zeroIndex === -1) {
        text += String.fromCharCode(...chunk);
        if (pos + chunk.byteLength >= file.size) return { text, truncated: true };
        pos += 64;
      } else {
        if (zeroIndex > 0) text += String.fromCharCode(...chunk.slice(0, zeroIndex));
        return { text, truncated: false };
      }
    }
    return { text, truncated: true };
  };
  const readMappedU32 = async (tableRva: number, index: number): Promise<number | null> => {
    const entryRva = tableRva + index * 4;
    const entryOff = rvaToOff(entryRva >>> 0);
    if (!isReadableOffset(entryOff) || entryOff + 4 > file.size) return null;
    const entryView = new DataView(await file.slice(entryOff, entryOff + 4).arrayBuffer());
    if (entryView.byteLength < 4) return null;
    return entryView.getUint32(0, true);
  };
  const readMappedU16 = async (tableRva: number, index: number): Promise<number | null> => {
    const entryRva = tableRva + index * 2;
    const entryOff = rvaToOff(entryRva >>> 0);
    if (!isReadableOffset(entryOff) || entryOff + 2 > file.size) return null;
    const entryView = new DataView(await file.slice(entryOff, entryOff + 2).arrayBuffer());
    if (entryView.byteLength < 2) return null;
    return entryView.getUint16(0, true);
  };

  const Characteristics = dv.getUint32(0, true);
  const TimeDateStamp = dv.getUint32(4, true);
  const MajorVersion = dv.getUint16(8, true);
  const MinorVersion = dv.getUint16(10, true);
  const NameRva = dv.getUint32(12, true);
  const OrdinalBase = dv.getUint32(16, true);
  const NumberOfFunctions = dv.getUint32(20, true);
  const NumberOfNames = dv.getUint32(24, true);
  const AddressOfFunctions = dv.getUint32(28, true);
  const AddressOfNames = dv.getUint32(32, true);
  const AddressOfNameOrdinals = dv.getUint32(36, true);
  const issues: string[] = [];
  const entries: Array<{ ordinal: number; rva: number; name: string | null; forwarder?: string | null }> = [];

  const namePtr = NameRva ? rvaToOff(NameRva) : null;
  let name = "";
  if (NameRva) {
    if (isReadableOffset(namePtr)) {
      const nameInfo = await readStr(namePtr);
      name = nameInfo.text;
      if (nameInfo.truncated) issues.push("Export DLL name string truncated.");
    } else {
      issues.push("Export DLL name RVA does not map to file data.");
    }
  }

  const funcTableOff = AddressOfFunctions ? rvaToOff(AddressOfFunctions) : null;
  const nameTableOff = AddressOfNames ? rvaToOff(AddressOfNames) : null;
  const ordTableOff = AddressOfNameOrdinals ? rvaToOff(AddressOfNameOrdinals) : null;

  if (isReadableOffset(funcTableOff)) {
    const functionNames = new Map<number, string>();
    if (NumberOfNames > 0) {
      if (!AddressOfNames || !isReadableOffset(nameTableOff)) {
        issues.push("Export name pointer table is missing or does not map while NumberOfNames is non-zero.");
      }
      if (!AddressOfNameOrdinals || !isReadableOffset(ordTableOff)) {
        issues.push("Export ordinal table is missing or does not map while NumberOfNames is non-zero.");
      }
    }
    if (AddressOfNames && AddressOfNameOrdinals && isReadableOffset(nameTableOff) && isReadableOffset(ordTableOff)) {
      for (let nameIndex = 0; nameIndex < NumberOfNames; nameIndex += 1) {
        const nameRva = await readMappedU32(AddressOfNames, nameIndex);
        const funcIndex = await readMappedU16(AddressOfNameOrdinals, nameIndex);
        if (nameRva == null || funcIndex == null) {
          if (nameIndex < NumberOfNames) {
            issues.push("Export name/ordinal tables are truncated; some names are missing.");
          }
          break;
        }
        if (funcIndex >= NumberOfFunctions) {
          issues.push(`Export ordinal table entry ${funcIndex} is out of range for ${NumberOfFunctions} functions.`);
          continue;
        }
        const nameOffset = rvaToOff(nameRva);
        if (isReadableOffset(nameOffset)) {
          const nameInfo = await readStr(nameOffset);
          functionNames.set(funcIndex, nameInfo.text);
          if (nameInfo.truncated) issues.push("Export name string truncated.");
        } else if (nameRva) {
          issues.push("Export name RVA does not map to file data.");
        }
      }
    }
    for (let idx = 0; idx < NumberOfFunctions; idx += 1) {
      const funcRva = await readMappedU32(AddressOfFunctions, idx);
      if (funcRva == null) {
        if (idx < NumberOfFunctions) {
          issues.push("Export address table is truncated; some function RVAs are missing.");
        }
        break;
      }
      const funcName: string | null = functionNames.get(idx) ?? null;
      let forwarder: string | null = null;
      if (funcRva >= dir.rva && funcRva < dir.rva + dir.size) {
        const fwdOff = rvaToOff(funcRva);
        if (isReadableOffset(fwdOff)) {
          const forwarderInfo = await readStr(fwdOff);
          forwarder = forwarderInfo.text;
          if (forwarderInfo.truncated) issues.push("Export forwarder string truncated.");
        } else if (funcRva) {
          issues.push("Export forwarder RVA does not map to file data.");
        }
      }
      entries.push({
        ordinal: OrdinalBase + idx,
        rva: funcRva,
        name: funcName,
        forwarder
      });
    }
  } else {
    issues.push("Export address table does not map to file offset.");
  }

  return {
    flags: Characteristics,
    timestamp: TimeDateStamp,
    version: ((MajorVersion << 16) | MinorVersion) >>> 0,
    dllName: name,
    Base: OrdinalBase,
    NumberOfFunctions,
    NumberOfNames,
    namePointerTable: AddressOfNames,
    ordinalTable: AddressOfNameOrdinals,
    entries,
    issues
  };
}
