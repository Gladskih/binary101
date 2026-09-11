"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import { readMappedNullTerminatedAsciiString } from "../strings/mapped-ascii-string.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";

export type PeExportEntry = {
  ordinal: number;
  rva: number;
  names: string[];
  forwarder?: string | null;
};

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
  entries: PeExportEntry[];
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
): Promise<Map<number, string[]>> => {
  const functionNames = new Map<number, string[]>();
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
    if (exportName != null) {
      const names = functionNames.get(funcIndex);
      if (names) names.push(exportName.text);
      else functionNames.set(funcIndex, [exportName.text]);
    }
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
  functionNames: Map<number, string[]>,
  readMappedU32: (tableRva: number, index: number) => Promise<number | null>,
  readForwarderStr: (rva: number) => Promise<{ text: string; issue?: string }>,
  rvaToOff: RvaToOffset,
  dir: PeDataDirectory,
  isReadableOffset: (offset: number | null) => offset is number,
  issues: string[]
): Promise<PeExportEntry[]> => {
  const entries: PeExportEntry[] = [];
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
      names: functionNames.get(idx) ?? [],
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
  if (dir.size < 40) {
    return {
      view: new DataView(new ArrayBuffer(0)),
      issue: "Export directory is smaller than the 40-byte IMAGE_EXPORT_DIRECTORY header."
    };
  }
  // Microsoft PE/COFF, Export Directory Table: the fixed header occupies 40 bytes.
  const view = await readMappedRvaPrefix(reader, dir.rva, 40, rvaToOff);
  return {
    view,
    issue: view.byteLength < 40 ? "Export directory header is truncated or no longer maps to file data." : null
  };
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
  const header = readExportHeader(directoryView.view);
  const issues: string[] = [];
  if (header.Characteristics !== 0) issues.push("Export directory flags are reserved and must be zero.");
  const name = await readExportDllName(reader, rvaToOff, header.NameRva,
    (offset): offset is number => offset != null && offset >= 0 && offset < reader.size, issues);
  const entries = await readDirectoryEntries(reader, header, dir, rvaToOff, issues);
  return {
    flags: header.Characteristics, timestamp: header.TimeDateStamp,
    version: ((header.MajorVersion << 16) | header.MinorVersion) >>> 0,
    dllName: name, Base: header.OrdinalBase,
    NumberOfFunctions: header.NumberOfFunctions, NumberOfNames: header.NumberOfNames,
    namePointerTable: header.AddressOfNames, ordinalTable: header.AddressOfNameOrdinals,
    entries, issues
  };
}

const readDirectoryEntries = async (
  reader: FileRangeReader,
  header: ExportDirectoryHeader,
  dir: PeDataDirectory,
  rvaToOff: RvaToOffset,
  issues: string[]
): Promise<PeExportEntry[]> => {
  const isReadableOffset = (offset: number | null): offset is number =>
    offset != null && offset >= 0 && offset < reader.size;
  // Microsoft PE/COFF: name/address pointers are DWORDs; ordinal indexes are WORDs.
  const readMappedU32 = async (tableRva: number, index: number): Promise<number | null> => {
    const view = await readMappedRvaPrefix(reader, tableRva + index * 4, 4, rvaToOff);
    return view.byteLength === 4 ? view.getUint32(0, true) : null;
  };
  const readMappedU16 = async (tableRva: number, index: number): Promise<number | null> => {
    const view = await readMappedRvaPrefix(reader, tableRva + index * 2, 2, rvaToOff);
    return view.byteLength === 2 ? view.getUint16(0, true) : null;
  };
  if (header.NumberOfFunctions === 0 && header.NumberOfNames === 0) return [];
  if (!header.AddressOfFunctions || !isReadableOffset(rvaToOff(header.AddressOfFunctions))) {
    issues.push("Export address table does not map to file offset.");
    return [];
  }
  const functionNames = canReadExportNameTables(header, rvaToOff(header.AddressOfNames),
    rvaToOff(header.AddressOfNameOrdinals), isReadableOffset, issues)
    ? await readExportNameMap(reader, rvaToOff, header, readMappedU32, readMappedU16, issues)
    : new Map<number, string[]>();
  return readExportEntries(header, functionNames, readMappedU32,
    rva => readExportForwarderString(reader, rvaToOff, dir.rva, dir.size, rva),
    rvaToOff, dir, isReadableOffset, issues);
};
