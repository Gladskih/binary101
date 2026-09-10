"use strict";

import { alignUpTo, bufferToHex, readAsciiString } from "../../binary-utils.js";
import type { ElfNoteEntry, ElfNotesInfo, ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { parseElfGnuProperties } from "./gnu-properties.js";
import { elfCoreNoteName, parseElfCoreNote } from "./core-notes.js";

const PT_NOTE = 4;
const SHT_NOTE = 7;

const NT_GNU_ABI_TAG = 1;
const NT_GNU_BUILD_ID = 3;
const NT_GNU_GOLD_VERSION = 4;
const NT_GNU_PROPERTY_TYPE_0 = 5;

const toSafeIndex = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

const decodeNoteType = (name: string, type: number): string | null => {
  if (name === "GNU") {
    if (type === NT_GNU_ABI_TAG) return "NT_GNU_ABI_TAG";
    if (type === NT_GNU_BUILD_ID) return "NT_GNU_BUILD_ID";
    if (type === NT_GNU_GOLD_VERSION) return "NT_GNU_GOLD_VERSION";
    if (type === NT_GNU_PROPERTY_TYPE_0) return "NT_GNU_PROPERTY_TYPE_0";
  }
  return null;
};

const decodeAbiOs = (value: number): string | null => {
  const map: Record<number, string> = {
    0: "Linux",
    1: "GNU",
    2: "Solaris",
    3: "FreeBSD"
  };
  return map[value] || null;
};

const describeNoteValue = (name: string, type: number, bytes: Uint8Array, littleEndian: boolean): string | null => {
  if (name === "GNU" && type === NT_GNU_BUILD_ID) {
    return bufferToHex(bytes);
  }
  if (name === "GNU" && type === NT_GNU_GOLD_VERSION) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const text = readAsciiString(dv, 0, dv.byteLength);
    return text.length ? text : null;
  }
  if (name === "GNU" && type === NT_GNU_ABI_TAG) {
    if (bytes.byteLength < 16) return null;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const os = dv.getUint32(0, littleEndian);
    const major = dv.getUint32(4, littleEndian);
    const minor = dv.getUint32(8, littleEndian);
    const sub = dv.getUint32(12, littleEndian);
    const osName = decodeAbiOs(os);
    const osLabel = osName ? `${osName} (os=${os})` : `os=${os}`;
    return `${osLabel} version ${major}.${minor}.${sub}`;
  }
  return null;
};

type ParsedNote = {
  entry: ElfNoteEntry;
  fileOffsetKey: string;
};

const parseNotesFromBytes = (
  bytes: Uint8Array,
  littleEndian: boolean,
  source: string,
  issues: string[],
  fileOffsetStart: bigint,
  wordSize: 4 | 8,
  coreMachine: number | undefined,
  seenNotes: ReadonlySet<string>
): ParsedNote[] => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const entries: ParsedNote[] = [];
  let offset = 0;
  while (offset + 12 <= dv.byteLength) {
    const noteStart = fileOffsetStart + BigInt(offset);
    const namesz = dv.getUint32(offset, littleEndian);
    const descsz = dv.getUint32(offset + 4, littleEndian);
    const type = dv.getUint32(offset + 8, littleEndian);
    offset += 12;

    const nameEnd = offset + namesz;
    if (nameEnd > dv.byteLength) {
      issues.push(`${source}: note name is truncated.`);
      break;
    }
    const nameRaw = readAsciiString(dv, offset, Math.min(namesz, dv.byteLength - offset));
    const name = nameRaw.replace(/\0.*$/, "");
    offset = alignUpTo(nameEnd, 4);

    const descEnd = offset + descsz;
    if (descEnd > dv.byteLength) {
      issues.push(`${source}: note desc is truncated.`);
      break;
    }
    const desc = bytes.subarray(offset, descEnd);
    offset = alignUpTo(descEnd, 4);
    if (seenNotes.has(noteStart.toString())) continue;

    const typeName = decodeNoteType(name, type);
    const value = describeNoteValue(name, type, desc, littleEndian);
    const description =
      name === "GNU" && type === NT_GNU_BUILD_ID
        ? "GNU build ID"
        : name === "GNU" && type === NT_GNU_ABI_TAG
          ? "GNU ABI tag"
          : name === "GNU" && type === NT_GNU_GOLD_VERSION
            ? "GNU gold version"
            : name === "GNU" && type === NT_GNU_PROPERTY_TYPE_0
              ? "GNU property note"
              : null;

    entries.push({
      fileOffsetKey: noteStart.toString(),
      entry: {
        source,
        name,
        type,
        typeName: coreMachine != null && (name === "CORE" || name === "LINUX")
          ? elfCoreNoteName(type) : typeName,
        description,
        value,
        descSize: descsz,
        ...(coreMachine != null && (name === "CORE" || name === "LINUX")
          ? { core: parseElfCoreNote(desc, type, wordSize,
            littleEndian ? "little" : "big", coreMachine) } : {}),
        ...(name === "GNU" && type === NT_GNU_PROPERTY_TYPE_0
          ? { properties: parseElfGnuProperties(desc, wordSize,
            littleEndian ? "little" : "big", issues) } : {})
      }
    });
  }
  return entries;
};

export async function parseElfNotes(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  littleEndian: boolean;
  is64?: boolean;
  coreMachine?: number;
}): Promise<ElfNotesInfo | null> {
  const issues: string[] = [];
  const ranges: Array<{ offset: bigint; size: bigint; source: string }> = [];

  opts.sections
    .filter(sec => sec.type === SHT_NOTE && sec.size > 0n)
    .forEach(sec => ranges.push({ offset: sec.offset, size: sec.size, source: sec.name ? `Section "${sec.name}"` : `SHT_NOTE section #${sec.index}` }));

  opts.programHeaders
    .filter(ph => (ph.type === PT_NOTE || ph.type === 0x6474e553) && ph.filesz > 0n)
    .forEach(ph => ranges.push({ offset: ph.offset, size: ph.filesz, source: `PT_NOTE segment #${ph.index}` }));

  if (!ranges.length) return null;

  const dedupe = new Set<string>();
  const seenNotes = new Set<string>();
  const all: ElfNoteEntry[] = [];
  for (const range of ranges) {
    const key = `${range.offset.toString()}-${range.size.toString()}`;
    if (dedupe.has(key)) continue;
    dedupe.add(key);

    const start = toSafeIndex(range.offset, `${range.source} offset`, issues);
    const size = toSafeIndex(range.size, `${range.source} size`, issues);
    if (start == null || size == null || size <= 0) continue;
    // Bound individual metadata reads even when a malformed note claims a huge segment.
    const end = Math.min(opts.file.size, start + size, start + 16 * 1024 * 1024);
    if (start >= opts.file.size || end <= start) {
      issues.push(`${range.source} falls outside the file.`);
      continue;
    }
    if (end !== start + size) issues.push(`${range.source} is truncated or exceeds the 16 MiB note limit.`);
    const bytes = new Uint8Array(await opts.file.slice(start, end).arrayBuffer());
    const parsedNotes = parseNotesFromBytes(bytes, opts.littleEndian, range.source, issues,
      range.offset, opts.is64 ? 8 : 4, opts.coreMachine, seenNotes);
    for (const parsed of parsedNotes) {
      if (seenNotes.has(parsed.fileOffsetKey)) continue;
      seenNotes.add(parsed.fileOffsetKey);
      all.push(parsed.entry);
    }
  }

  return { entries: all, issues };
}

