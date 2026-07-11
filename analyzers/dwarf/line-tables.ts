"use strict";

import {
  DWARF_ENCODING,
  DWARF_FORM,
  DWARF_LIMIT,
  DWARF_LINE_CONTENT,
  DWARF_SECTION,
  DWARF_VERSION
} from "./constants.js";
import { DwarfCursor } from "./cursor.js";
import type { DwarfLineFile, DwarfSectionSource } from "./types.js";

type EntryFormat = { content: bigint; form: bigint };
type EntryValue = string | bigint | null;
type TableReadContext = {
  sections: Map<string, DwarfSectionSource>;
  littleEndian: boolean;
  issues: string[];
  dwarfFormat: 32 | 64;
};
export type DwarfLineTables = {
  directoryCount: number;
  fileCount: number;
  files: DwarfLineFile[];
};

const FIXED_FORM_BYTE_LENGTHS = new Map<number, number>([
  [DWARF_FORM.data1, Uint8Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.data2, Uint16Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.data4, Uint32Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.data8, BigUint64Array.BYTES_PER_ELEMENT]
]);

const safeCount = (cursor: DwarfCursor, value: bigint, label: string): number | null => {
  if (value > BigInt(DWARF_LIMIT.maximumLineTableEntries)) {
    cursor.fail(`${label} count ${value.toString()} exceeds the analysis limit`);
    return null;
  }
  return Number(value);
};

const readReferencedString = async (
  context: TableReadContext,
  sectionName: string,
  offset: bigint
): Promise<string | null> => {
  const source = context.sections.get(sectionName);
  if (!source) {
    context.issues.push(`${sectionName}: required by a line table but not available.`);
    return null;
  }
  if (offset > BigInt(Number.MAX_SAFE_INTEGER) || offset >= BigInt(source.section.size)) {
    context.issues.push(
      `${sectionName}: line table string offset ${offset.toString()} is outside the section.`
    );
    return null;
  }
  return new DwarfCursor(
    source.reader,
    source.section,
    Number(offset),
    source.section.size,
    context.littleEndian,
    context.issues
  ).cstring();
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
    return cursor.skip(DWARF_ENCODING.data16Bytes) ? null : undefined;
  }
  if (form === DWARF_FORM.lineStringPointer || form === DWARF_FORM.stringPointer) {
    const offset = await cursor.unsigned(context.dwarfFormat / DWARF_ENCODING.bitsPerByte);
    if (offset == null) return undefined;
    return readReferencedString(
      context,
      form === DWARF_FORM.lineStringPointer ? DWARF_SECTION.lineStrings : DWARF_SECTION.strings,
      offset
    );
  }
  cursor.fail(`Unsupported line table form 0x${form.toString(16)}`);
  return undefined;
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

const readVersionFiveEntries = async (
  cursor: DwarfCursor,
  formats: EntryFormat[],
  context: TableReadContext,
  entryKind: "directories" | "files"
): Promise<{ count: number; files: DwarfLineFile[] } | null> => {
  const encodedCount = await cursor.uleb();
  if (encodedCount == null) return null;
  const count = safeCount(cursor, encodedCount, "Line table entry");
  if (count == null) return null;
  const files: DwarfLineFile[] = [];
  for (let entryIndex = 0; entryIndex < count; entryIndex += 1) {
    let path = "";
    let directoryIndex: bigint | null = null;
    for (const format of formats) {
      const value = await readEntryValue(cursor, format, context);
      if (value === undefined) return null;
      if (format.content === BigInt(DWARF_LINE_CONTENT.path) && typeof value === "string") {
        path = value;
      } else if (format.content === BigInt(DWARF_LINE_CONTENT.directoryIndex) &&
                 typeof value === "bigint") {
        directoryIndex = value;
      }
    }
    if (entryKind === "files" && files.length < DWARF_LIMIT.maximumLineFilesStored) {
      files.push({ path, directoryIndex });
    }
  }
  return { count, files };
};

const readLegacyTables = async (cursor: DwarfCursor): Promise<DwarfLineTables | null> => {
  let directoryCount = 0;
  while (true) {
    const directory = await cursor.cstring();
    if (directory == null) return null;
    if (!directory.length) break;
    directoryCount += 1;
    if (directoryCount > DWARF_LIMIT.maximumLineTableEntries) {
      cursor.fail("Directory count exceeds the analysis limit");
      return null;
    }
  }
  let fileCount = 0;
  const files: DwarfLineFile[] = [];
  while (true) {
    const path = await cursor.cstring();
    if (path == null) return null;
    if (!path.length) break;
    const directoryIndex = await cursor.uleb();
    const timestamp = await cursor.uleb();
    const size = await cursor.uleb();
    if (directoryIndex == null || timestamp == null || size == null) return null;
    fileCount += 1;
    if (fileCount > DWARF_LIMIT.maximumLineTableEntries) {
      cursor.fail("File count exceeds the analysis limit");
      return null;
    }
    if (files.length < DWARF_LIMIT.maximumLineFilesStored) files.push({ path, directoryIndex });
  }
  return { directoryCount, fileCount, files };
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
  return files && { directoryCount: directories.count, fileCount: files.count, files: files.files };
};
