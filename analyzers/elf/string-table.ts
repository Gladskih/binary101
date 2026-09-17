import type { FileRangeReader } from "../file-range-reader.js";

type StringTableRange = { offset: number; size: number };

const validTableRange = (fileSize: number, strings: StringTableRange | null):
strings is StringTableRange => strings != null && Number.isSafeInteger(strings.offset) &&
  Number.isSafeInteger(strings.size) && strings.offset >= 0 && strings.size >= 0 &&
  strings.size <= fileSize - strings.offset;

// gABI 4: a nonempty table begins and ends with NUL; empty tables permit index zero.
// https://gabi.xinuos.com/elf/04-strtab.html
const validateStringTable = async (
  reader: FileRangeReader, strings: StringTableRange | null, issues: string[]
): Promise<boolean> => {
  if (!validTableRange(reader.size, strings)) {
    issues.push("ELF string table has an invalid file range.");
    return false;
  }
  if (!strings.size) return true;
  if ((await reader.readBytes(strings.offset, 1))[0] !== 0) {
    issues.push("ELF string table must begin with NUL.");
  }
  if ((await reader.readBytes(strings.offset + strings.size - 1, 1))[0] !== 0) {
    issues.push("ELF string table must end with NUL.");
  }
  return true;
};

const validStringIndex = (size: number, offset: number): boolean =>
  Number.isSafeInteger(offset) && offset >= 0 &&
  (offset < size || (offset === 0 && size === 0));

const readTableString = async (
  reader: FileRangeReader, strings: StringTableRange, offset: number, issues: string[]
): Promise<string | null> => {
  if (!validStringIndex(strings.size, offset)) {
    issues.push("ELF string has an invalid string table offset/reference.");
    return null;
  }
  if (offset === 0) return "";
  const decoder = new TextDecoder();
  const parts: string[] = [];
  const limit = strings.size - offset;
  for (let consumed = 0; consumed < limit;) {
    const bytes = await reader.readBytes(strings.offset + offset + consumed,
      Math.min(limit - consumed, 4096));
    if (!bytes.length) break;
    const end = bytes.indexOf(0);
    if (end >= 0) return parts.join("") + decoder.decode(bytes.subarray(0, end));
    parts.push(decoder.decode(bytes, { stream: true }));
    consumed += bytes.length;
  }
  issues.push("ELF string is unterminated.");
  return null;
};

export const createElfStringTableReader = (
  reader: FileRangeReader, strings: StringTableRange | null, issues: string[]
): ((offset: number) => Promise<string | null>) => {
  // Share in-flight reads too: DT_NEEDED can reference the same name concurrently.
  const cache = new Map<number, Promise<string | null>>();
  let validated: Promise<boolean> | undefined;
  return async offset => {
    validated ??= validateStringTable(reader, strings, issues);
    if (!await validated || !strings) return null;
    if (!cache.has(offset)) cache.set(offset, readTableString(reader, strings, offset, issues));
    return cache.get(offset)!;
  };
};
