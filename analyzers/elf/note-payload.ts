import { bufferToHex, readAsciiString } from "../../binary-utils.js";
import type { ElfNoteEntry } from "./types.js";
import type { ElfByteOrder } from "./binary-layout-types.js";
import { ELF_INTEGER_READERS } from "./byte-order.js";
import { parseElfGnuProperties } from "./gnu-properties.js";
import { elfCoreNoteName, parseElfCoreNote } from "./core-notes.js";

const abiVersion = (bytes: Uint8Array, order: ElfByteOrder): string | null => {
  if (bytes.length < 16) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const read = ELF_INTEGER_READERS[order];
  const os = read.u32(view, 0);
  const osName = ({ 0: "Linux", 1: "GNU", 2: "Solaris", 3: "FreeBSD" } as Record<number, string>)[os];
  return `${osName ? `${osName} (os=${os})` : `os=${os}`} version ` +
    `${read.u32(view, 4)}.${read.u32(view, 8)}.${read.u32(view, 12)}`;
};

// GNU note IDs: https://raw.githubusercontent.com/bminor/glibc/master/elf/elf.h
const gnuNotes: Readonly<Record<number, {
  name: string; description: string;
  value?: (bytes: Uint8Array, order: ElfByteOrder) => string | null;
  properties?: typeof parseElfGnuProperties;
}>> = {
  1: { name: "NT_GNU_ABI_TAG", description: "GNU ABI tag", value: abiVersion },
  3: { name: "NT_GNU_BUILD_ID", description: "GNU build ID", value: bufferToHex },
  4: { name: "NT_GNU_GOLD_VERSION", description: "GNU gold version", value: bytes =>
    readAsciiString(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength), 0, bytes.byteLength) || null },
  5: { name: "NT_GNU_PROPERTY_TYPE_0", description: "GNU property note", properties: parseElfGnuProperties }
};

export const decodeElfNotePayload = (entry: ElfNoteEntry, bytes: Uint8Array,
  wordSize: 4 | 8, order: ElfByteOrder, coreMachine: number | undefined, issues: string[]): void => {
  if (coreMachine != null && (entry.name === "CORE" || entry.name === "LINUX")) {
    entry.typeName = elfCoreNoteName(entry.type);
    entry.core = parseElfCoreNote(bytes, entry.type, wordSize, order, coreMachine);
    return;
  }
  const descriptor = entry.name === "GNU" ? gnuNotes[entry.type] : undefined;
  if (!descriptor) return;
  entry.typeName = descriptor.name;
  entry.description = descriptor.description;
  entry.value = descriptor.value?.(bytes, order) ?? null;
  if (descriptor.properties) entry.properties = descriptor.properties(bytes, wordSize, order, issues);
};
