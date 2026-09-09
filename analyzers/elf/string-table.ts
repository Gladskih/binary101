import type { FileRangeReader } from "../file-range-reader.js";

export const createElfStringTableReader = (
  reader: FileRangeReader, strings: { offset: number; size: number } | null, issues: string[]
): ((offset: number) => Promise<string>) => {
  const cache = new Map<number, string>();
  return async offset => {
    const cached = cache.get(offset);
    if (cached != null) return cached;
    if (!strings || offset >= strings.size) {
      issues.push("ELF string has an invalid string table reference.");
      return "";
    }
    const bytes: number[] = [];
    // Resource policy: a metadata name cannot allocate unbounded memory.
    const limit = Math.min(strings.size - offset, 65536);
    for (let index = 0; index < limit; index += 1) {
      const view = await reader.read(strings.offset + offset + index, 1);
      if (!view.byteLength) break;
      if (view.getUint8(0) === 0) {
        const name = new TextDecoder().decode(new Uint8Array(bytes));
        cache.set(offset, name);
        return name;
      }
      bytes.push(view.getUint8(0));
    }
    issues.push("ELF string is unterminated or exceeds the 64 KiB name limit.");
    return "";
  };
};
