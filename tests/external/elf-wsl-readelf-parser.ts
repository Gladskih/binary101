"use strict";
const DISPLAYABLE_DYNSYM_TYPES = new Set(["NOTYPE", "OBJECT", "FUNC", "TLS", "IFUNC", "GNU_IFUNC"]);
export interface ReadelfHeaderInfo {
  className: string;
  littleEndian: boolean;
  typeToken: string;
  entry: bigint;
  phoff: number;
  shoff: number;
  flags: number;
  ehsize: number;
  phentsize: number;
  phnum: number;
  shentsize: number;
  shnum: number;
  shstrndx: number;
}
export interface ReadelfProgramHeaderInfo {
  type: string;
  offset: bigint;
  vaddr: bigint;
  paddr: bigint;
  filesz: bigint;
  memsz: bigint;
  flagsMask: number;
  align: bigint;
}
export interface ReadelfSectionInfo {
  index: number;
  name: string;
  type: string;
  addr: bigint;
  off: bigint;
  size: bigint;
  entsize: bigint;
  link: number;
  info: number;
  align: number;
  flagsMask: bigint;
}
export interface ReadelfDynamicInfo {
  needed: string[];
  soname: string | null;
  rpath: string | null;
  runpath: string | null;
  init: bigint | null;
  fini: bigint | null;
  preinitArray: { vaddr: bigint; size: bigint } | null;
  initArray: { vaddr: bigint; size: bigint } | null;
  finiArray: { vaddr: bigint; size: bigint } | null;
  flags: Set<string>;
  flags1: Set<string>;
}
export interface ReadelfDynSymbolsInfo {
  imports: Set<string>;
  exports: Set<string>;
}
export interface ReadelfSnapshot {
  header: ReadelfHeaderInfo;
  programHeaders: ReadelfProgramHeaderInfo[];
  sections: ReadelfSectionInfo[];
  dynamic: ReadelfDynamicInfo | null;
  dynSymbols: ReadelfDynSymbolsInfo | null;
  buildId: string | null;
}
const toHexBigInt = (value: string): bigint => BigInt(`0x${value.replace(/^0x/i, "")}`);
const readField = (text: string, label: string): string | null => {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = text.match(new RegExp(`^\\s*${escaped}:\\s*(.+)$`, "m"));
  const value = match?.[1];
  return typeof value === "string" ? value.trim() : null;
};
const parseLeadingDec = (value: string | null): number | null => {
  if (!value) return null;
  const match = value.match(/^(\d+)/);
  const parsed = match?.[1];
  return typeof parsed === "string" ? Number.parseInt(parsed, 10) : null;
};
const parseHex = (value: string | null): bigint | null => {
  if (!value) return null;
  const match = value.match(/0x([0-9a-fA-F]+)/);
  const parsed = match?.[1];
  return typeof parsed === "string" ? BigInt(`0x${parsed}`) : null;
};
const parseHexU32 = (value: string | null): number | null => {
  const parsed = parseHex(value);
  if (parsed == null || parsed > 0xffffffffn) return null;
  return Number(parsed);
};
const collectLinesBetween = (lines: string[], startMarker: string, endMarker: string): string[] => {
  const out: string[] = [];
  let inBlock = false;
  for (const line of lines) {
    if (!inBlock && line.includes(startMarker)) {
      inBlock = true;
      continue;
    }
    if (inBlock && endMarker && line.includes(endMarker)) break;
    if (inBlock) out.push(line);
  }
  return out;
};
const parseHeader = (dump: string): ReadelfHeaderInfo | null => {
  const className = readField(dump, "Class");
  const dataValue = readField(dump, "Data");
  const typeValue = readField(dump, "Type");
  const entry = parseHex(readField(dump, "Entry point address"));
  const phoff = parseLeadingDec(readField(dump, "Start of program headers"));
  const shoff = parseLeadingDec(readField(dump, "Start of section headers"));
  const flags = parseHexU32(readField(dump, "Flags"));
  const ehsize = parseLeadingDec(readField(dump, "Size of this header"));
  const phentsize = parseLeadingDec(readField(dump, "Size of program headers"));
  const phnum = parseLeadingDec(readField(dump, "Number of program headers"));
  const shentsize = parseLeadingDec(readField(dump, "Size of section headers"));
  const shnum = parseLeadingDec(readField(dump, "Number of section headers"));
  const shstrndx = parseLeadingDec(readField(dump, "Section header string table index"));
  if (
    !className || !dataValue || !typeValue || entry == null || phoff == null || shoff == null || flags == null ||
    ehsize == null || phentsize == null || phnum == null || shentsize == null || shnum == null || shstrndx == null
  ) {
    return null;
  }
  return {
    className,
    littleEndian: dataValue.toLowerCase().includes("little endian"),
    typeToken: typeValue.split(/\s+/)[0] || "",
    entry,
    phoff,
    shoff,
    flags,
    ehsize,
    phentsize,
    phnum,
    shentsize,
    shnum,
    shstrndx
  };
};
const parseProgramHeaders = (lines: string[]): ReadelfProgramHeaderInfo[] => {
  const block = collectLinesBetween(lines, "Program Headers:", "Section to Segment mapping:");
  const out: ReadelfProgramHeaderInfo[] = [];
  for (const line of block) {
    const match = line.match(
      /^\s*(\S+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+([RWE ]{0,3})\s+(0x[0-9a-fA-F]+)\s*$/
    );
    if (!match) continue;
    const [, type = "", offset = "", vaddr = "", paddr = "", filesz = "", memsz = "", flags = "", align = ""] = match;
    if (!type || !offset || !vaddr || !paddr || !filesz || !memsz || !align) continue;
    const flagText = flags.replace(/\s+/g, "");
    const flagsMask = (flagText.includes("R") ? 4 : 0) | (flagText.includes("W") ? 2 : 0) | (flagText.includes("E") ? 1 : 0);
    out.push({
      type,
      offset: toHexBigInt(offset),
      vaddr: toHexBigInt(vaddr),
      paddr: toHexBigInt(paddr),
      filesz: toHexBigInt(filesz),
      memsz: toHexBigInt(memsz),
      flagsMask,
      align: toHexBigInt(align)
    });
  }
  return out;
};
const parseSections = (lines: string[]): ReadelfSectionInfo[] => {
  const block = collectLinesBetween(lines, "Section Headers:", "Program Headers:");
  const out: ReadelfSectionInfo[] = [];
  for (let index = 0; index < block.length; index += 1) {
    const headerLine = block[index];
    if (!headerLine) continue;
    const headerMatch = headerLine.match(/^\s*\[\s*(\d+)\]\s*(.*)$/);
    if (!headerMatch) continue;
    const line2 = block[index + 1] ?? "";
    const line3 = block[index + 2] ?? "";
    const infoMatch = line2.match(
      /^\s*(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$/
    );
    const flagsMatch = line3.match(/^\s*\[([0-9a-fA-F]+)\]:\s*(.*)$/);
    if (!infoMatch || !flagsMatch) continue;
    const sectionIndex = headerMatch[1] ?? "";
    const name = headerMatch[2] ?? "";
    const [, type = "", addr = "", off = "", size = "", entsize = "", link = "", info = "", align = ""] = infoMatch;
    const flagsMask = flagsMatch[1] ?? "";
    const sectionFields = [sectionIndex, type, addr, off, size, entsize, link, info, align, flagsMask];
    if (sectionFields.some(value => !value)) continue;
    out.push({
      index: Number.parseInt(sectionIndex, 10),
      name: name.trim(),
      type,
      addr: toHexBigInt(addr),
      off: toHexBigInt(off),
      size: toHexBigInt(size),
      entsize: toHexBigInt(entsize),
      link: Number.parseInt(link, 10),
      info: Number.parseInt(info, 10),
      align: Number.parseInt(align, 10),
      flagsMask: toHexBigInt(flagsMask)
    });
    index += 2;
  }
  return out;
};
const parseFlagsWordSet = (value: string | null): Set<string> => {
  if (!value) return new Set<string>();
  const cleaned = value.replace(/^Flags:\s*/i, "").trim();
  const words = cleaned.split(/\s+/).filter(token => token.length && !token.startsWith("0x"));
  return new Set(words);
};
const parseDynamic = (lines: string[]): ReadelfDynamicInfo | null => {
  const tagValues = new Map<string, string[]>();
  let inDynamic = false;
  for (const line of lines) {
    if (line.startsWith("Dynamic section at offset")) {
      inDynamic = true;
      continue;
    }
    if (!inDynamic) continue;
    if (line.startsWith("Symbol table '.dynsym'") || line.startsWith("Displaying notes found in:")) break;
    const entryMatch = line.match(/^\s*0x[0-9a-fA-F]+\s+\(([^)]+)\)\s+(.*)$/);
    if (!entryMatch) continue;
    const tag = entryMatch[1]?.trim();
    const value = entryMatch[2]?.trim();
    if (!tag || value == null) continue;
    const values = tagValues.get(tag);
    if (values) values.push(value);
    else tagValues.set(tag, [value]);
  }
  if (!inDynamic) return null;
  const all = (tag: string): string[] => tagValues.get(tag) || [];
  const first = (tag: string): string | null => tagValues.get(tag)?.[0] ?? null;
  const bracketText = (value: string | null): string | null => {
    const match = value?.match(/\[([^\]]+)\]/);
    return match?.[1] ?? null;
  };
  const bytesValue = (value: string | null): bigint | null => {
    const size = parseLeadingDec(value);
    return size == null ? null : BigInt(size);
  };
  const arrayValue = (baseTag: string, sizeTag: string): { vaddr: bigint; size: bigint } | null => {
    const vaddr = parseHex(first(baseTag));
    const size = bytesValue(first(sizeTag));
    if (vaddr == null || size == null || vaddr === 0n || size === 0n) return null;
    return { vaddr, size };
  };
  return {
    needed: all("NEEDED").map(text => bracketText(text)).filter((value): value is string => Boolean(value)),
    soname: bracketText(first("SONAME")),
    rpath: bracketText(first("RPATH")),
    runpath: bracketText(first("RUNPATH")),
    init: parseHex(first("INIT")),
    fini: parseHex(first("FINI")),
    preinitArray: arrayValue("PREINIT_ARRAY", "PREINIT_ARRAYSZ"),
    initArray: arrayValue("INIT_ARRAY", "INIT_ARRAYSZ"),
    finiArray: arrayValue("FINI_ARRAY", "FINI_ARRAYSZ"),
    flags: parseFlagsWordSet(first("FLAGS")),
    flags1: parseFlagsWordSet(first("FLAGS_1"))
  };
};
const normalizeDynsymName = (rawName: string): string => rawName.replace(/@{1,2}.*/, "");
const parseDynSymbols = (lines: string[]): ReadelfDynSymbolsInfo | null => {
  let inDynsym = false;
  const imports = new Set<string>();
  const exports = new Set<string>();
  for (const line of lines) {
    if (line.startsWith("Symbol table '.dynsym'")) {
      inDynsym = true;
      continue;
    }
    if (!inDynsym) continue;
    if (line.trim() === "" && (imports.size || exports.size)) break;
    const entryMatch = line.match(/^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)\s*(.*)$/);
    if (!entryMatch) continue;
    const type = entryMatch[1] ?? "";
    const bind = entryMatch[2] ?? "";
    const ndx = entryMatch[3] ?? "";
    const rawName = ((entryMatch[4] ?? "").trim().split(/\s+/)[0] || "").trim();
    const name = normalizeDynsymName(rawName);
    if (!name || bind === "LOCAL" || !DISPLAYABLE_DYNSYM_TYPES.has(type)) continue;
    if (ndx === "UND") imports.add(name);
    else exports.add(name);
  }
  if (!inDynsym) return null;
  return { imports, exports };
};
const parseBuildId = (dump: string): string | null => {
  const match = dump.match(/Build ID:\s*([0-9a-fA-F]+)/);
  return match?.[1]?.toLowerCase() || null;
};
export const parseReadelfDump = (dump: string): ReadelfSnapshot | null => {
  const header = parseHeader(dump);
  if (!header) return null;
  const lines = dump.split(/\r?\n/);
  return {
    header,
    programHeaders: parseProgramHeaders(lines),
    sections: parseSections(lines),
    dynamic: parseDynamic(lines),
    dynSymbols: parseDynSymbols(lines),
    buildId: parseBuildId(dump)
  };
};
