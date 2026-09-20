import type { ElfNoteEntry } from "./types.js";
import type { ElfByteOrder } from "./binary-layout-types.js";

interface BuildAttributeDefinition {
  readonly name: string;
  readonly kinds: string;
  readonly values?: readonly string[];
}

// Note types, attribute tags, printable-name range and kind characters:
// https://fedoraproject.org/wiki/Toolchain/Watermark#Proposed_Specification_for_non-loaded_notes
export const gnuBuildAttributeTypes: Readonly<Partial<Record<number, string>>> = {
  0x100: "GNU_BUILD_ATTRIBUTE_OPEN",
  0x101: "GNU_BUILD_ATTRIBUTE_FUNC"
};

// Accepted kinds and numeric labels: print_gnu_build_attribute_name, including
// legacy boolean stack-protector attributes and numeric ABI attributes.
// https://github.com/RTEMS/sourceware-mirror-binutils-gdb/blob/master/binutils/readelf.c
const attributeDefinitions: Readonly<Partial<Record<number, BuildAttributeDefinition>>> = {
  1: { name: "Version", kinds: "$" },
  2: { name: "Stack protector", kinds: "!+*", values: ["off", "on", "all", "strong", "explicit"] },
  3: { name: "RELRO", kinds: "!+" },
  4: { name: "Stack size", kinds: "*" },
  5: { name: "Compiler", kinds: "$" },
  6: { name: "ABI", kinds: "$*" },
  7: { name: "PIC / PIE", kinds: "*", values: ["static", "pic", "PIC", "pie", "PIE"] },
  8: { name: "Short enums", kinds: "!+" }
};

const textDecoder = new TextDecoder();

function acceptsKind(kind: string, definition: BuildAttributeDefinition | undefined): boolean {
  return (definition?.kinds ?? "*$!+").includes(kind);
}

function attributeValue(kind: string, bytes: Uint8Array,
  definition: BuildAttributeDefinition | undefined): string | null {
  if (!acceptsKind(kind, definition)) return null;
  switch (kind) {
    case "+": return bytes.length === 0 ? "true" : null;
    case "!": return bytes.length === 0 ? "false" : null;
    case "$": return bytes.includes(0) ? null : textDecoder.decode(bytes);
    default: return numericValue(bytes, definition?.values);
  }
}

function numericValue(bytes: Uint8Array, labels: readonly string[] | undefined): string | null {
  // readelf's uint64_t limit; empty numeric payloads are accepted for old GCC plugins.
  if (bytes.length > 8) return null;
  // Watermark numeric values are little endian independently of EI_DATA.
  // Shift by eight bits per byte; BigInt preserves all 64 bits.
  const value = bytes.reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);
  return labels?.[Number(value)] ?? `0x${value.toString(16)}`;
}

function namedAttribute(bytes: Uint8Array, start: number,
  kind: string): { name: string; value: string | null } | null {
  const end = bytes.indexOf(0, start);
  // The last NUL can terminate a boolean name, but cannot also terminate its value.
  if (kind === "+" || kind === "!") {
    if (end !== bytes.length - 1) return null;
    return { name: textDecoder.decode(bytes.subarray(start, end)),
      value: kind === "+" ? "true" : "false" };
  }
  if (end >= bytes.length - 1) return null;
  return { name: textDecoder.decode(bytes.subarray(start, end)),
    value: attributeValue(kind, bytes.subarray(end + 1, bytes.length - 1), undefined) };
}

function decodeName(bytes: Uint8Array): { name: string; value: string | null } | null {
  // A legacy name needs kind + attribute + NUL; version 2 adds the two-byte "GA" prefix.
  if (bytes.length < 3 || bytes[bytes.length - 1] !== 0) return null;
  const start = String.fromCharCode(bytes[0]!, bytes[1]!) === "GA" ? 2 : 0;
  if (bytes.length < start + 3) return null;
  const attribute = bytes[start + 1]!;
  const kind = String.fromCharCode(bytes[start]!);
  const definition = attributeDefinitions[attribute];
  // Watermark reserves 0..31 for short tags; 32..126 start printable names.
  if (attribute < 32) return {
    name: definition?.name ?? `Attribute ${attribute}`,
    value: attributeValue(kind, bytes.subarray(start + 2, bytes.length - 1), definition)
  };
  if (attribute > 126) return null;
  return namedAttribute(bytes, start + 1, kind);
}

function decodeRange(bytes: Uint8Array, order: ElfByteOrder): string | null {
  // readelf print_gnu_build_attribute_description accepts a legacy single uint32,
  // two uint32 addresses or two uint64 addresses, all in the ELF byte order.
  if (![4, 8, 16].includes(bytes.length)) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const start = bytes.length === 16 ? view.getBigUint64(0, order === "little") :
    BigInt(view.getUint32(0, order === "little"));
  let end = 0n;
  if (bytes.length === 16) end = view.getBigUint64(8, order === "little");
  if (bytes.length === 8) end = BigInt(view.getUint32(4, order === "little"));
  if (end !== 0n && end < start) return null;
  if (end === 0n) return `From 0x${start.toString(16)}`;
  return `0x${start.toString(16)}–0x${end.toString(16)} (end exclusive)`;
}

export function decodeBuildAttributeNote(entry: ElfNoteEntry, name: Uint8Array,
  bytes: Uint8Array, order: ElfByteOrder, ranges: Map<number, string>, issues: string[]): void {
  if (gnuBuildAttributeTypes[entry.type] == null) {
    issues.push(`${entry.source}: Invalid GNU build attribute note type.`);
    return;
  }
  entry.kind = "gnu-build-attribute";
  entry.typeName = null;
  const decoded = decodeName(name);
  entry.value = decoded?.value ?? null;
  if (decoded) entry.name = decoded.name;
  if (entry.value == null) {
    issues.push(`${entry.source}: Invalid or truncated GNU build attribute name, numeric value or encoding.`);
  }
  // The caller owns the sequential parse state: empty descriptors inherit the
  // nearest preceding range of the same note type (Watermark description field).
  if (bytes.length) {
    const range = decodeRange(bytes, order);
    if (range == null) {
      ranges.delete(entry.type);
      issues.push(`${entry.source}: Invalid GNU build attribute range.`);
    } else ranges.set(entry.type, range);
  }
  entry.description = ranges.get(entry.type) ?? "Range unavailable";
}
