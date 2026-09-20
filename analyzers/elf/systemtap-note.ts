import type { ElfByteOrder } from "./binary-layout-types.js";

// Three ELF-word addresses followed by provider, name and argument strings.
// https://github.com/RTEMS/sourceware-mirror-binutils-gdb/blob/master/binutils/readelf.c
// print_stapsdt_note validates each terminating NUL independently.
export const decodeSystemTapNote = (bytes: Uint8Array, wordSize: 4 | 8,
  order: ElfByteOrder, issues: string[]): string | null => {
  if (bytes.length < wordSize * 3) {
    issues.push("SystemTap descriptor is truncated.");
    return null;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const addresses = [0, wordSize, wordSize * 2].map(offset => `0x${(wordSize === 8
    ? view.getBigUint64(offset, order === "little") : view.getUint32(offset, order === "little")).toString(16)}`);
  const strings: string[] = [];
  let offset = wordSize * 3;
  for (let index = 0; index < 3; index++) {
    const end = bytes.indexOf(0, offset);
    if (end < 0) {
      issues.push("SystemTap descriptor has a truncated string.");
      return null;
    }
    strings.push(new TextDecoder().decode(bytes.subarray(offset, end)));
    offset = end + 1;
  }
  return `${strings[0]}:${strings[1]}; location ${addresses[0]}; base ${addresses[1]}; ` +
    `semaphore ${addresses[2]}; arguments: ${strings[2] || "none"}`;
};
