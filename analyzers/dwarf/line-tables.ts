import { DwarfStringReader } from "./strings.js";
"use strict";

import {
  DWARF_ENCODING,
  DWARF_FORM,
  DWARF_LINE_CONTENT,
  DWARF_SECTION,
  DWARF_VERSION
} from "./constants.js";
import type { DwarfCursor } from "./cursor.js";
import type { DwarfLineFile, DwarfSectionSource } from "./types.js";

type EntryFormat = { content: bigint; form: bigint };
type EntryValue = string | bigint | Uint8Array | null;
type TableReadContext = {
  sections: Map<string, DwarfSectionSource>;
  littleEndian: boolean;
  issues: string[];
  dwarfFormat: 32 | 64;
  strings?: DwarfStringReader;
};
export type DwarfLineTables = {
  directories: string[];
  files: DwarfLineFile[];
};

const FIXED_FORM_BYTE_LENGTHS = new Map<number, number>([
  [DWARF_FORM.data1, Uint8Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.data2, Uint16Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.data4, Uint32Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.data8, BigUint64Array.BYTES_PER_ELEMENT]
]);

const safeCount = (cursor: DwarfCursor, value: bigint, label: string): number | null => {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    cursor.fail(`${label} count ${value.toString()} cannot be represented exactly`);
    return null;
  }
  return Number(value);
};

const readReferencedString = async (
  context: TableReadContext,
  sectionName: string,
  offset: bigint
): Promise<string | null> => {
  const strings = context.strings ?? new DwarfStringReader(context.sections,
    context.littleEndian ? "little" : "big", context.issues);
  return strings.resolve({ kind: "string-offset", sectionName, value: offset }, {
    version: 5, format: context.dwarfFormat, addressSize: 0, stringOffsetsBase: null
  });
};

const readEntryValue = async (
  cursor: DwarfCursor,
  format: EntryFormat,
  context: TableReadContext
): Promise<EntryValue | undefined> => {
  const form = Number(format.form);
  if (form === DWARF_FORM.string) return (await cursor.cstring()) ?? undefined;
  if (form === DWARF_FORM.unsignedData) return (await cursor.uleb()) ?? undefined;
  const fixedBytes = FIXED_FORM_BYTE_LENGTHS.get(form);
  if (fixedBytes != null) return (await cursor.unsigned(fixedBytes)) ?? undefined;
  if (form === DWARF_FORM.data16) {
    return (await cursor.bytes(DWARF_ENCODING.data16Bytes)) ?? undefined;
  }
  return readEntryStringPointer(cursor, form, context);
};

const readEntryStringPointer = async (
  cursor: DwarfCursor, form: number, context: TableReadContext
): Promise<EntryValue | undefined> => {
  if (form !== DWARF_FORM.lineStringPointer && form !== DWARF_FORM.stringPointer) {
    cursor.fail(`Unsupported line table form 0x${form.toString(16)}`);
    return undefined;
  }
  const offset = await cursor.unsigned(context.dwarfFormat / DWARF_ENCODING.bitsPerByte);
  if (offset == null) return undefined;
  return readReferencedString(context,
    form === DWARF_FORM.lineStringPointer ? DWARF_SECTION.lineStrings : DWARF_SECTION.strings, offset);
};

const readFormats = async (cursor: DwarfCursor): Promise<EntryFormat[] | null> => {
  const count = await cursor.uint8();
  if (count == null) return null;
  const formats: EntryFormat[] = [];
  for (let index = 0; index < count; index += 1) {
    const content = await cursor.uleb();
    const form = await cursor.uleb();
    if (content == null || form == null) return null;
    formats.push({ content, form });
  }
  return formats;
};

const numericContent = new Map<bigint, "directoryIndex" | "timestamp" | "size">([
  [BigInt(DWARF_LINE_CONTENT.directoryIndex), "directoryIndex"],
  [BigInt(DWARF_LINE_CONTENT.timestamp), "timestamp"], [BigInt(DWARF_LINE_CONTENT.size), "size"]
]);

const assignLineContent = (file: DwarfLineFile, content: bigint, value: EntryValue): void => {
  if (typeof value === "bigint") {
    const key = numericContent.get(content);
    if (key) file[key] = value;
  } else if (content === BigInt(DWARF_LINE_CONTENT.path) && typeof value === "string") file.path = value;
  else if (content === BigInt(DWARF_LINE_CONTENT.md5) && value instanceof Uint8Array) file.md5 = value;
};

const readVersionFiveEntry = async (cursor: DwarfCursor, formats: EntryFormat[],
  context: TableReadContext): Promise<DwarfLineFile | null> => {
  const file: DwarfLineFile = { path: "", directoryIndex: null };
  for (const format of formats) {
    const value = await readEntryValue(cursor, format, context);
    if (value === undefined) return null;
    assignLineContent(file, format.content, value);
  }
  return file;
};

const readVersionFiveEntries = async (
  cursor: DwarfCursor,
  formats: EntryFormat[],
  context: TableReadContext,
  entryKind: "directories" | "files"
): Promise<DwarfLineFile[] | null> => {
  const encodedCount = await cursor.uleb();
  if (encodedCount == null) return null;
  const count = safeCount(cursor, encodedCount, "Line table entry");
  if (count == null) return null;
  if (count > cursor.end - cursor.position || (count > 0 && !formats.length)) {
    cursor.fail(`Line ${entryKind} count cannot fit in the remaining header bytes`);
    return null;
  }
  const files: DwarfLineFile[] = [];
  for (let entryIndex = 0; entryIndex < count; entryIndex += 1) {
    const entry = await readVersionFiveEntry(cursor, formats, context);
    if (!entry) return null;
    files.push(entry);
  }
  return files;
};

const readLegacyTables = async (cursor: DwarfCursor): Promise<DwarfLineTables | null> => {
  const directories: string[] = [];
  while (true) {
    const directory = await cursor.cstring();
    if (directory == null) return null;
    if (!directory.length) break;
    directories.push(directory);
  }
  const files: DwarfLineFile[] = [];
  while (true) {
    const path = await cursor.cstring();
    if (path == null) return null;
    if (!path.length) break;
    const directoryIndex = await cursor.uleb();
    const timestamp = await cursor.uleb();
    const size = await cursor.uleb();
    if ([directoryIndex, timestamp, size].includes(null)) return null;
    files.push({ path, directoryIndex, timestamp: timestamp!, size: size! });
  }
  return { directories, files };
};

export const readDwarfLineTables = async (
  cursor: DwarfCursor,
  version: number,
  context: TableReadContext
): Promise<DwarfLineTables | null> => {
  if (version < DWARF_VERSION.maximumSupported) return readLegacyTables(cursor);
  const directoryFormats = await readFormats(cursor);
  if (!directoryFormats) return null;
  const directories = await readVersionFiveEntries(
    cursor, directoryFormats, context, "directories"
  );
  const fileFormats = await readFormats(cursor);
  if (!directories || !fileFormats) return null;
  const files = await readVersionFiveEntries(cursor, fileFormats, context, "files");
  return files && { directories: directories.map(entry => entry.path), files };
};
