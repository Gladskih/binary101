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

type ExportDirectoryHeader = {
  Characteristics: number; TimeDateStamp: number; MajorVersion: number; MinorVersion: number;
  NameRva: number; OrdinalBase: number; NumberOfFunctions: number; NumberOfNames: number;
  AddressOfFunctions: number; AddressOfNames: number;
  AddressOfNameOrdinals: number;
};

type ExportFunctionNameRead = { text: string; terminated: boolean };

const createEmptyExportDirectory = (issues: string[]): PeExportDirectoryResult => ({
  flags: 0, timestamp: 0, version: 0, dllName: "", Base: 0,
  NumberOfFunctions: 0, NumberOfNames: 0, namePointerTable: 0, ordinalTable: 0, entries: [], issues
});

const readExportHeader = (dv: DataView): ExportDirectoryHeader => ({
  Characteristics: dv.getUint32(0, true), TimeDateStamp: dv.getUint32(4, true),
  MajorVersion: dv.getUint16(8, true), MinorVersion: dv.getUint16(10, true),
  NameRva: dv.getUint32(12, true), OrdinalBase: dv.getUint32(16, true),
  NumberOfFunctions: dv.getUint32(20, true), NumberOfNames: dv.getUint32(24, true),
  AddressOfFunctions: dv.getUint32(28, true), AddressOfNames: dv.getUint32(32, true),
  AddressOfNameOrdinals: dv.getUint32(36, true)
});

const readExportDllName = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  nameRva: number,
  isReadableOffset: (offset: number | null) => offset is number,
  issues: string[]
): Promise<string> => {
  if (!nameRva) return "";
  if (!isReadableOffset(rvaToOff(nameRva))) {
    issues.push("Export DLL name RVA does not map to file data.");
    return "";
  }
  const nameInfo = await readMappedNullTerminatedAsciiString(reader, reader.size, rvaToOff, nameRva >>> 0, reader.size);
  if (!nameInfo) return "";
  if (!nameInfo.terminated) issues.push("Export DLL name string truncated.");
  return nameInfo.text;
};

const readExportNameMap = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  header: ExportDirectoryHeader,
  readMappedU32: (tableRva: number, index: number) => Promise<number | null>,
  readMappedU16: (tableRva: number, index: number) => Promise<number | null>,
  issues: string[]
): Promise<Map<number, string>> => {
  const functionNames = new Map<number, string>();
  let previousExportName: string | null = null;
  let canCheckNameSorting = header.NumberOfNames > 1;
  let namePointerTableIsSorted = true;
  for (let nameIndex = 0; nameIndex < header.NumberOfNames; nameIndex += 1) {
    const nameRva = await readMappedU32(header.AddressOfNames, nameIndex);
    const funcIndex = await readMappedU16(header.AddressOfNameOrdinals, nameIndex);
    if (nameRva == null || funcIndex == null) {
      issues.push("Export name/ordinal tables are truncated; some names are missing.");
      canCheckNameSorting = false;
      break;
    }
    const exportName = await readExportFunctionName(reader, rvaToOff, nameRva, issues);
    if (exportName == null || !exportName.terminated) canCheckNameSorting = false;
    if (exportName != null && previousExportName != null && previousExportName > exportName.text) {
      namePointerTableIsSorted = false;
    }
    if (exportName != null) previousExportName = exportName.text;
    if (funcIndex >= header.NumberOfFunctions) {
      issues.push(`Export ordinal table entry ${funcIndex} is out of range for ${header.NumberOfFunctions} functions.`);
      continue;
    }
    if (exportName != null) functionNames.set(funcIndex, exportName.text);
  }
  if (canCheckNameSorting && !namePointerTableIsSorted) {
    issues.push("Export name pointer table is not sorted lexically; the PE loader expects it to support binary search.");
  }
  return functionNames;
};

const readExportFunctionName = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  nameRva: number,
  issues: string[]
): Promise<ExportFunctionNameRead | null> => {
  const nameOffset = rvaToOff(nameRva);
  if (nameOffset == null || nameOffset < 0 || nameOffset >= reader.size) {
    if (nameRva) issues.push("Export name RVA does not map to file data.");
    return null;
  }
  const nameInfo = await readMappedNullTerminatedAsciiString(reader, reader.size, rvaToOff, nameRva >>> 0, reader.size);
  if (!nameInfo) return null;
  if (!nameInfo.terminated) issues.push("Export name string truncated.");
  return { text: nameInfo.text, terminated: nameInfo.terminated };
};

const readExportEntries = async (
  header: ExportDirectoryHeader,
  functionNames: Map<number, string>,
  readMappedU32: (tableRva: number, index: number) => Promise<number | null>,
  readForwarderStr: (rva: number) => Promise<{ text: string; issue?: string }>,
  rvaToOff: RvaToOffset,
  dir: PeDataDirectory,
  isReadableOffset: (offset: number | null) => offset is number,
  issues: string[]
): Promise<Array<{ ordinal: number; rva: number; name: string | null; forwarder?: string | null }>> => {
  const entries: Array<{ ordinal: number; rva: number; name: string | null; forwarder?: string | null }> = [];
  for (let idx = 0; idx < header.NumberOfFunctions; idx += 1) {
    const funcRva = await readMappedU32(header.AddressOfFunctions, idx);
    if (funcRva == null) {
      issues.push("Export address table is truncated; some function RVAs are missing.");
      break;
    }
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
      ordinal: header.OrdinalBase + idx,
      rva: funcRva,
      name: functionNames.get(idx) ?? null,
      forwarder
    });
  }
  return entries;
};

const canReadExportNameTables = (
  header: ExportDirectoryHeader,
  nameTableOff: number | null,
  ordTableOff: number | null,
  isReadableOffset: (offset: number | null) => offset is number,
  issues: string[]
): boolean => {
  if (header.NumberOfNames <= 0) return false;
  if (!header.AddressOfNames || !isReadableOffset(nameTableOff)) {
    issues.push("Export name pointer table is missing or does not map while NumberOfNames is non-zero.");
  }
  if (!header.AddressOfNameOrdinals || !isReadableOffset(ordTableOff)) {
    issues.push("Export ordinal table is missing or does not map while NumberOfNames is non-zero.");
  }
  return Boolean(
    header.AddressOfNames && header.AddressOfNameOrdinals &&
    isReadableOffset(nameTableOff) && isReadableOffset(ordTableOff)
  );
};

const getExportDirectoryView = async (
  reader: FileRangeReader,
  dir: PeDataDirectory,
  rvaToOff: RvaToOffset
): Promise<{ view: DataView; issue: string | null }> => {
  const base = rvaToOff(dir.rva);
  if (base == null) return { view: new DataView(new ArrayBuffer(0)), issue: "Export directory RVA does not map to file data." };
  if (base < 0 || base >= reader.size) return { view: new DataView(new ArrayBuffer(0)), issue: "Export directory starts outside file data." };
  const availableDirSize = Math.max(0, Math.min(dir.size, reader.size - base));
  if (availableDirSize < 40) {
    return {
      view: new DataView(new ArrayBuffer(0)),
      issue: "Export directory is smaller than the 40-byte IMAGE_EXPORT_DIRECTORY header."
    };
  }
  return { view: await reader.read(base, 40), issue: null };
};

const readExportForwarderString = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  exportRva: number,
  exportSize: number,
  rva: number
): Promise<{ text: string; issue?: string }> => {
  if (rva < exportRva || rva >= exportRva + exportSize) {
    return { text: "", issue: "Export forwarder RVA lies outside the export directory range." };
  }
  const forwarderInfo = await readMappedNullTerminatedAsciiString(
    reader,
    reader.size,
    rvaToOff,
    rva >>> 0,
    exportRva + exportSize - rva
  );
  if (!forwarderInfo) return { text: "", issue: "Export forwarder RVA does not map to file data." };
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
  const directoryView = await getExportDirectoryView(reader, dir, rvaToOff);
  if (directoryView.issue) return createEmptyExportDirectory([directoryView.issue]);
  const isReadableOffset = (offset: number | null): offset is number =>
    offset != null && offset >= 0 && offset < reader.size;
  const readForwarderStr = (rva: number): Promise<{ text: string; issue?: string }> =>
    readExportForwarderString(reader, rvaToOff, dir.rva, dir.size, rva);
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
  const header = readExportHeader(directoryView.view);
  const issues: string[] = [];
  const entries: Array<{ ordinal: number; rva: number; name: string | null; forwarder?: string | null }> = [];
  if (header.Characteristics !== 0) issues.push("Export directory flags are reserved and must be zero.");
  const name = await readExportDllName(reader, rvaToOff, header.NameRva, isReadableOffset, issues);
  const funcTableOff = header.AddressOfFunctions ? rvaToOff(header.AddressOfFunctions) : null;
  const nameTableOff = header.AddressOfNames ? rvaToOff(header.AddressOfNames) : null;
  const ordTableOff = header.AddressOfNameOrdinals ? rvaToOff(header.AddressOfNameOrdinals) : null;
  if (header.NumberOfFunctions === 0 && header.NumberOfNames === 0) {
    // Empty export directories can still carry a DLL name; there is no EAT slot to map.
  } else if (isReadableOffset(funcTableOff)) {
    let functionNames = new Map<number, string>();
    if (canReadExportNameTables(header, nameTableOff, ordTableOff, isReadableOffset, issues)) {
      functionNames = await readExportNameMap(reader, rvaToOff, header, readMappedU32, readMappedU16, issues);
    }
    entries.push(
      ...await readExportEntries(
        header,
        functionNames,
        readMappedU32,
        readForwarderStr,
        rvaToOff,
        dir,
        isReadableOffset,
        issues
      )
    );
  } else {
    issues.push("Export address table does not map to file offset.");
  }
  return {
    flags: header.Characteristics, timestamp: header.TimeDateStamp,
    version: ((header.MajorVersion << 16) | header.MinorVersion) >>> 0,
    dllName: name, Base: header.OrdinalBase,
    NumberOfFunctions: header.NumberOfFunctions, NumberOfNames: header.NumberOfNames,
    namePointerTable: header.AddressOfNames, ordinalTable: header.AddressOfNameOrdinals,
    entries, issues
  };
}
