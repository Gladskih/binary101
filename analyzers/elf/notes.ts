"use strict";

import { alignUpTo, bufferToHex, readAsciiString } from "../../binary-utils.js";
import type { ElfNoteEntry, ElfNotesInfo, ElfProgramHeader, ElfSectionHeader } from "./types.js";

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

const parseNotesFromBytes = (
  bytes: Uint8Array,
  littleEndian: boolean,
  source: string,
  issues: string[]
): ElfNoteEntry[] => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const entries: ElfNoteEntry[] = [];
  let offset = 0;
  while (offset + 12 <= dv.byteLength) {
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
      source,
      name,
      type,
      typeName,
      description,
      value,
      descSize: descsz
    });
  }
  return entries;
};

export async function parseElfNotes(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  littleEndian: boolean;
}): Promise<ElfNotesInfo | null> {
  const issues: string[] = [];
  const ranges: Array<{ offset: bigint; size: bigint; source: string }> = [];

  opts.programHeaders
    .filter(ph => ph.type === PT_NOTE && ph.filesz > 0n)
    .forEach(ph => ranges.push({ offset: ph.offset, size: ph.filesz, source: `PT_NOTE segment #${ph.index}` }));

  opts.sections
    .filter(sec => sec.type === SHT_NOTE && sec.size > 0n)
    .forEach(sec => ranges.push({ offset: sec.offset, size: sec.size, source: sec.name ? `Section "${sec.name}"` : `SHT_NOTE section #${sec.index}` }));

  if (!ranges.length) return null;

  const dedupe = new Set<string>();
  const all: ElfNoteEntry[] = [];
  for (const range of ranges) {
    const key = `${range.offset.toString()}-${range.size.toString()}`;
    if (dedupe.has(key)) continue;
    dedupe.add(key);

    const start = toSafeIndex(range.offset, `${range.source} offset`, issues);
    const size = toSafeIndex(range.size, `${range.source} size`, issues);
    if (start == null || size == null || size <= 0) continue;
    const end = Math.min(opts.file.size, start + size);
    if (start >= opts.file.size || end <= start) {
      issues.push(`${range.source} falls outside the file.`);
      continue;
    }
    if (end !== start + size) issues.push(`${range.source} is truncated.`);
    const bytes = new Uint8Array(await opts.file.slice(start, end).arrayBuffer());
    all.push(...parseNotesFromBytes(bytes, opts.littleEndian, range.source, issues));
  }

  return { entries: all, issues };
}

