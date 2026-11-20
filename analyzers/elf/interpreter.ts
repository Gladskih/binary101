import { isPrintableByte } from "../../binary-utils.js";
import { DEFAULT_FILE_READ_WINDOW_BYTES } from "../file-range-reader.js";
import type { ElfInterpreterInfo, ElfProgramHeader } from "./types.js";

// gABI 7.2: PT_INTERP provides the range of a NUL-terminated interpreter pathname.
// https://gabi.xinuos.com/elf/07-pheader.html#segment-types
const PT_INTERP = 3;

const displayPath = (bytes: Uint8Array, issues: string[]): string => {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    issues.push("PT_INTERP pathname contains non-UTF-8 data, shown with escaped bytes.");
    return Array.from(bytes, byte => isPrintableByte(byte) && byte !== 0x5c
      ? String.fromCharCode(byte) : `\\x${byte.toString(16).padStart(2, "0")}`).join("");
  }
};

export async function parseElfInterpreter(
  file: File,
  programHeaders: ElfProgramHeader[]
): Promise<ElfInterpreterInfo | null> {
  const issues: string[] = [];
  const interp = programHeaders.find(ph => ph.type === PT_INTERP);
  if (!interp) return null;
  if (interp.offset < 0n || interp.offset >= BigInt(file.size) || interp.filesz <= 0n) return {
    path: "", issues: ["PT_INTERP is empty or falls outside the file."]
  };
  const offset = Number(interp.offset);
  const size = Math.min(Number(interp.filesz), file.size - offset);
  if (size < interp.filesz) issues.push("PT_INTERP is truncated.");
  const length = Math.min(size, DEFAULT_FILE_READ_WINDOW_BYTES);
  const bytes = new Uint8Array(await file.slice(offset, offset + length).arrayBuffer());
  const terminator = bytes.indexOf(0);
  if (terminator === -1) issues.push(size === length ? "PT_INTERP pathname is missing its NUL terminator." :
    "PT_INTERP pathname preview reached the read limit before the NUL terminator.");
  if (terminator === 0) issues.push("PT_INTERP pathname is empty.");
  return { path: displayPath(bytes.subarray(0, terminator < 0 ? bytes.length : terminator), issues), issues };
}
