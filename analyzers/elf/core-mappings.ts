import type { ElfCoreNote, ElfCoreMapping } from "./core-note-types.js";
import type { ElfCoreNoteReader } from "./core-note-reader.js";

// NT_FILE: count, page size, count triples, NUL-terminated filenames.
// https://raw.githubusercontent.com/torvalds/linux/master/fs/binfmt_elf.c (fill_files_note)
export const parseElfCoreMappings = (reader: ElfCoreNoteReader): ElfCoreNote => {
  const mappings: ElfCoreMapping[] = [];
  const result: ElfCoreNote = { fields: [], mappings, issues: reader.issues };
  if (!reader.contains(0, reader.wordSize * 2)) return result;
  const count = reader.unsigned(0);
  result.fields.push({ name: "Page size", value: reader.unsigned(reader.wordSize) });
  if (count > 100000n || count * BigInt(3 * reader.wordSize) >
    BigInt(reader.bytes.length - reader.wordSize * 2)) {
    reader.issues.push("NT_FILE mapping count exceeds the descriptor or 100000 entry limit.");
    return result;
  }
  let pathOffset = (2 + Number(count) * 3) * reader.wordSize;
  for (let index = 0; index < Number(count); index += 1) {
    const offset = (2 + index * 3) * reader.wordSize;
    const end = reader.bytes.indexOf(0, pathOffset);
    if (end < 0) {
      reader.issues.push("NT_FILE filename is not NUL-terminated.");
      break;
    }
    mappings.push({ start: reader.unsigned(offset), end: reader.unsigned(offset + reader.wordSize),
      pageOffset: reader.unsigned(offset + reader.wordSize * 2),
      path: reader.text(pathOffset, end - pathOffset) });
    pathOffset = end + 1;
  }
  if (mappings.some(mapping => mapping.end < mapping.start)) {
    reader.issues.push("NT_FILE contains an inverted mapping range.");
  }
  return result;
};

// https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/auxvec.h
export const parseElfCoreAuxv = (reader: ElfCoreNoteReader): ElfCoreNote => {
  const auxv = [];
  for (let offset = 0; reader.contains(offset, reader.wordSize * 2); offset += reader.wordSize * 2) {
    const tag = reader.unsigned(offset);
    auxv.push({ tag, value: reader.unsigned(offset + reader.wordSize) });
    if (tag === 0n) return { fields: [], auxv, issues: reader.issues };
    if (auxv.length === 100000) break;
  }
  reader.issues.push("NT_AUXV has no AT_NULL terminator within the descriptor or entry limit.");
  return { fields: [], auxv, issues: reader.issues };
};
