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
  if (!dir?.rva || dir.size < 40) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  addCoverageRegion("EXPORT directory", base, dir.size);
  const dv = new DataView(await file.slice(base, base + dir.size).arrayBuffer());
  const tableSize = Math.min(40, dv.byteLength);
  if (tableSize < 40) return null;
  const readStr = async (offset: number): Promise<string> => {
    if (offset < 0 || offset >= file.size) return "";
    let text = "";
    let pos = offset;
    while (text.length < 1024) {
      const chunk = new Uint8Array(await file.slice(pos, pos + 64).arrayBuffer());
      const zeroIndex = chunk.indexOf(0);
      if (zeroIndex === -1) {
        text += String.fromCharCode(...chunk);
        pos += 64;
      } else {
        if (zeroIndex > 0) text += String.fromCharCode(...chunk.slice(0, zeroIndex));
        break;
      }
    }
    return text;
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

  const namePtr = rvaToOff(NameRva);
  const name = namePtr != null ? await readStr(namePtr) : "";

  const funcTableOff = rvaToOff(AddressOfFunctions);
  const nameTableOff = rvaToOff(AddressOfNames);
  const ordTableOff = rvaToOff(AddressOfNameOrdinals);

  if (funcTableOff != null) {
    const funcTable = new DataView(
      await file
        .slice(funcTableOff, funcTableOff + NumberOfFunctions * 4)
        .arrayBuffer()
    );
    const nameTable =
      nameTableOff != null
        ? new DataView(await file.slice(nameTableOff, nameTableOff + NumberOfNames * 4).arrayBuffer())
        : null;
    const ordTable =
      ordTableOff != null
        ? new DataView(await file.slice(ordTableOff, ordTableOff + NumberOfNames * 2).arrayBuffer())
        : null;
    const functionNames = new Map<number, string>();
    if (nameTable && ordTable) {
      const maxNames = Math.min(
        NumberOfNames,
        Math.floor(nameTable.byteLength / 4),
        Math.floor(ordTable.byteLength / 2)
      );
      for (let nameIndex = 0; nameIndex < maxNames; nameIndex += 1) {
        const nameRva = nameTable.getUint32(nameIndex * 4, true);
        const funcIndex = ordTable.getUint16(nameIndex * 2, true);
        const nameOffset = rvaToOff(nameRva);
        if (nameOffset != null) {
          functionNames.set(funcIndex, await readStr(nameOffset));
        }
      }
    }
    const maxFuncs = Math.min(NumberOfFunctions, Math.floor(funcTable.byteLength / 4));
    for (let idx = 0; idx < maxFuncs; idx += 1) {
      const funcRva = funcTable.getUint32(idx * 4, true);
      const funcName: string | null = functionNames.get(idx) ?? null;
      let forwarder: string | null = null;
      if (funcRva >= dir.rva && funcRva < dir.rva + dir.size) {
        const fwdOff = rvaToOff(funcRva);
        if (fwdOff != null) {
          forwarder = await readStr(fwdOff);
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
    version: (MajorVersion << 16) | MinorVersion,
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
