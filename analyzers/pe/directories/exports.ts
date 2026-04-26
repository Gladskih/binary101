"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedNullTerminatedAsciiString } from "../strings/mapped-ascii-string.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";

type PeExportDirectoryResult = {
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
};

const createEmptyExportDirectory = (issues: string[]): PeExportDirectoryResult => ({
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
  issues
});

export async function parseExportDirectory(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<PeExportDirectoryResult | null> {
  const dir = dataDirs.find(d => d.name === "EXPORT");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  if (dir.rva === 0) {
    return createEmptyExportDirectory(["Export directory has a non-zero size but RVA is 0."]);
  }
  if (dir.size === 0) {
    return createEmptyExportDirectory(["Export directory has an RVA but size is 0."]);
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    return createEmptyExportDirectory(["Export directory RVA does not map to file data."]);
  }
  if (base < 0 || base >= reader.size) {
    return createEmptyExportDirectory(["Export directory starts outside file data."]);
  }
  const availableDirSize = Math.max(0, Math.min(dir.size, reader.size - base));
  if (availableDirSize < 40) {
    return createEmptyExportDirectory([
      "Export directory is smaller than the 40-byte IMAGE_EXPORT_DIRECTORY header."
    ]);
  }
  const dv = await reader.read(base, 40);
  const isReadableOffset = (offset: number | null): offset is number =>
    offset != null && offset >= 0 && offset < reader.size;
  const readForwarderStr = async (rva: number): Promise<{ text: string; issue?: string }> => {
    if (rva < dir.rva || rva >= dir.rva + dir.size) {
      return { text: "", issue: "Export forwarder RVA lies outside the export directory range." };
    }
    const forwarderInfo = await readMappedNullTerminatedAsciiString(
      reader,
      reader.size,
      rvaToOff,
      rva >>> 0,
      dir.rva + dir.size - rva
    );
    if (!forwarderInfo) {
      return { text: "", issue: "Export forwarder RVA does not map to file data." };
    }
    if (forwarderInfo.terminated) return { text: forwarderInfo.text };
    if (forwarderInfo.mappingStopped) {
      return {
        text: forwarderInfo.text,
        issue: "Export forwarder string stops mapping before its NUL terminator within the export directory range."
      };
    }
    return {
      text: forwarderInfo.text,
      issue: "Export forwarder string is not NUL-terminated within the export directory range."
    };
  };
  const readMappedU32 = async (tableRva: number, index: number): Promise<number | null> => {
    const entryRva = tableRva + index * 4;
    const entryOff = rvaToOff(entryRva >>> 0);
    if (!isReadableOffset(entryOff) || entryOff + 4 > reader.size) return null;
    const entryView = await reader.read(entryOff, 4);
    if (entryView.byteLength < 4) return null;
    return entryView.getUint32(0, true);
  };
  const readMappedU16 = async (tableRva: number, index: number): Promise<number | null> => {
    const entryRva = tableRva + index * 2;
    const entryOff = rvaToOff(entryRva >>> 0);
    if (!isReadableOffset(entryOff) || entryOff + 2 > reader.size) return null;
    const entryView = await reader.read(entryOff, 2);
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
      const nameInfo = await readMappedNullTerminatedAsciiString(
        reader,
        reader.size,
        rvaToOff,
        NameRva >>> 0,
        reader.size
      );
      if (nameInfo) {
        name = nameInfo.text;
        if (!nameInfo.terminated) issues.push("Export DLL name string truncated.");
      }
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
          const nameInfo = await readMappedNullTerminatedAsciiString(
            reader,
            reader.size,
            rvaToOff,
            nameRva >>> 0,
            reader.size
          );
          if (nameInfo) {
            functionNames.set(funcIndex, nameInfo.text);
            if (!nameInfo.terminated) issues.push("Export name string truncated.");
          }
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
          const forwarderInfo = await readForwarderStr(funcRva);
          forwarder = forwarderInfo.text;
          if (forwarderInfo.issue) issues.push(forwarderInfo.issue);
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
