import type { ElfNoteEntry } from "./types.js";
import type { ElfByteOrder } from "./binary-layout-types.js";

// Encoding and range inheritance: binutils readelf.c, print_gnu_build_attribute_*.
// https://github.com/RTEMS/sourceware-mirror-binutils-gdb/blob/master/binutils/readelf.c
function attributeValue(kind: number, bytes: Uint8Array, attribute: number): string | null {
  if (kind === 43) return "true";
  if (kind === 33) return "false";
  if (kind === 36) return new TextDecoder().decode(bytes);
  if (kind !== 42 || bytes.length > 8) return null;
  // Numeric name payloads are little endian regardless of ELF byte order.
  const value = bytes.reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);
  return (attribute === 2 ? ["off", "on", "all", "strong", "explicit"] :
    attribute === 7 ? ["static", "pic", "PIC", "pie", "PIE"] : [])[Number(value)] ??
    `0x${value.toString(16)}`;
}

function attributeName(attribute: number, bytes: Uint8Array): string {
  return ({ 1: "Version", 2: "Stack protector", 3: "RELRO", 4: "Stack size",
    5: "Compiler", 6: "ABI", 7: "PIC / PIE", 8: "Short enums"
  } as Record<number, string>)[attribute] ?? (attribute < 32 ? `Attribute ${attribute}` :
    new TextDecoder().decode(bytes));
}

function decodeName(entry: ElfNoteEntry, bytes: Uint8Array, issues: string[]): void {
  const start = bytes[0] === 71 && bytes[1] === 65 ? 2 : 0;
  if (bytes.length < start + 3 || bytes[bytes.length - 1] !== 0) {
    issues.push(`${entry.source}: GNU build attribute name is truncated.`);
    return;
  }
  const attribute = bytes[start + 1]!;
  const end = attribute < 32 ? start + 2 : bytes.indexOf(0, start + 1);
  entry.name = attributeName(attribute, bytes.subarray(start + 1, end));
  const value = attributeValue(bytes[start]!, bytes.subarray(
    attribute < 32 ? end : end + 1, bytes.length - 1), attribute);
  if (value == null) issues.push(`${entry.source}: Invalid GNU build attribute numeric value or encoding.`);
  entry.value = value;
}

function decodeRange(bytes: Uint8Array, order: ElfByteOrder): string | null {
  if (![4, 8, 16].includes(bytes.length)) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const start = bytes.length === 16 ? view.getBigUint64(0, order === "little") :
    BigInt(view.getUint32(0, order === "little"));
  const end = bytes.length === 16 ? view.getBigUint64(8, order === "little") :
    bytes.length === 8 ? BigInt(view.getUint32(4, order === "little")) : 0n;
  if (end !== 0n && end < start) return null;
  return end === 0n ? `From 0x${start.toString(16)}` :
    `0x${start.toString(16)}–0x${end.toString(16)} (end exclusive)`;
}

export const decodeBuildAttributeNote = (entry: ElfNoteEntry, name: Uint8Array,
  bytes: Uint8Array, order: ElfByteOrder, ranges: Map<number, string>, issues: string[]): void => {
  entry.typeName = entry.type === 0x100 ? "GNU_BUILD_ATTRIBUTE_OPEN" : "GNU_BUILD_ATTRIBUTE_FUNC";
  decodeName(entry, name, issues);
  if (bytes.length) {
    const range = decodeRange(bytes, order);
    if (range == null) {
      ranges.delete(entry.type);
      issues.push(`${entry.source}: Invalid GNU build attribute range.`);
    } else ranges.set(entry.type, range);
  }
  entry.description = ranges.get(entry.type) ?? "Range unavailable";
};
