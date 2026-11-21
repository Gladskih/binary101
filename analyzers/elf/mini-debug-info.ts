import { readElfImageHeaders } from "./image-headers.js";
import { elfFileRange } from "./relocation-reader.js";
import { parseElfSymbolTables, type ElfSymbolTable } from "./symbol-tables.js";
import type { ElfParseResult, ElfSectionHeader } from "./types.js";

export interface ElfMiniDebugInfo {
  sections: ElfSectionHeader[];
  symbolTables: ElfSymbolTable[];
  issues: string[];
}

// MiniDebugInfo needs random access to the embedded ELF. Cap retained output so
// compressed input cannot allocate an unbounded in-browser buffer.
const MAX_MINI_DEBUG_BYTES = 64 * 1024 * 1024;

const unpackMiniDebug = async (stream: ReadableStream<Uint8Array>): Promise<File> => {
  const { XzReadableStream } = await import("xz-decompress");
  const reader = new XzReadableStream(stream).getReader();
  const chunks: BlobPart[] = [];
  let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return new File(chunks, ".gnu_debugdata");
      size += value.byteLength;
      if (size > MAX_MINI_DEBUG_BYTES) {
        await reader.cancel();
        throw new Error("decoded data exceeds 64 MiB");
      }
      if (value.byteLength) chunks.push(new Uint8Array(value));
    }
  } finally {
    reader.releaseLock();
  }
};

// GDB MiniDebugInfo embeds an XZ-compressed symbol-bearing ELF.
// https://sourceware.org/gdb/current/onlinedocs/gdb.html/MiniDebugInfo.html
export const parseElfMiniDebugInfo = async (
  file: File, elf: ElfParseResult
): Promise<ElfMiniDebugInfo | null> => {
  const section = elf.sections.find(item => item.name === ".gnu_debugdata");
  if (!section) return null;
  const range = elfFileRange(section.offset, section.size, file.size);
  if (!range?.size || section.type !== 1 || (section.flags & 0x800n)) {
    return { sections: [], symbolTables: [], issues: [".gnu_debugdata has an invalid section or file range."] };
  }
  try {
    const debugFile = await unpackMiniDebug(file.slice(range.offset, range.offset + range.size).stream());
    const inner = await readElfImageHeaders(debugFile);
    if (!inner || "incompleteHeader" in inner || !inner.sections.length) {
      return { sections: [], symbolTables: [], issues: [
        ".gnu_debugdata did not yield a readable ELF section table.", ...(inner?.issues ?? [])
      ] };
    }
    if (inner.header.machine !== elf.header.machine || inner.is64 !== elf.is64 ||
        inner.littleEndian !== elf.littleEndian) {
      return { sections: [], symbolTables: [], issues: [
        "Embedded ELF machine, class or byte order differs from the main ELF.", ...inner.issues
      ] };
    }
    const symbolTables = await parseElfSymbolTables(debugFile, inner);
    return { sections: inner.sections, symbolTables, issues: inner.issues };
  } catch (error) {
    return { sections: [], symbolTables: [], issues: [`.gnu_debugdata XZ decode failed: ${String(error)}.`] };
  }
};
