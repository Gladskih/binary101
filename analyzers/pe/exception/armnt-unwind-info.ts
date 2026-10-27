import type { PeLanguageHandler } from "./types.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { mappedRvaSize } from "../rva-mapping.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import { summarizeArmntOpcodeSequences, type ArmntOpcodeSummary } from "./armnt-opcodes.js";

// ARMNT differs from ARM64: lengths use 2-byte units, F occupies bit22,
// Epilogue Count starts at bit23, and Code Words occupies bits28..31.
// https://learn.microsoft.com/en-us/cpp/build/arm-exception-handling
export interface ArmntUnwindInfo {
  functionLengthBytes: number;
  handlerRva: number | null;
  languageHandler?: PeLanguageHandler;
  hasHandler: boolean;
  fragment: boolean;
  version: number | null;
  opcodes?: ArmntOpcodeSummary;
}

const languageHandler = (rva: number, size: number, handlerRva: number | null) => handlerRva ? {
  languageHandler: { unwindInfoRva: rva, handlerRva: handlerRva - (handlerRva & 1), dataRva: rva + size }
} : {};

const readWord = async (reader: FileRangeReader, rvaToOff: RvaToOffset, rva: number): Promise<number | null> => {
  const view = await readMappedRvaPrefix(reader, rva, 4, rvaToOff);
  return view.byteLength === 4 ? view.getUint32(0, true) : null;
};

const packedIssue = (word: number): string | null => {
  const savesLinkRegister = (word & (1 << 20)) !== 0;
  if (((word >>> 13) & 3) === 0 && !savesLinkRegister) {
    return "ARMNT packed unwind returns via POP PC without saving LR.";
  }
  if ((word & (1 << 21)) !== 0) {
    if (!savesLinkRegister) return "ARMNT packed unwind declares a frame chain without saving LR.";
    if ((word & (1 << 19)) === 0 && ((word >>> 16) & 7) === 7) {
      return "ARMNT packed unwind includes r11 both in Reg and in its frame chain.";
    }
  }
  return null;
};

const readPacked = (word: number, issues: string[]): ArmntUnwindInfo | null => {
  const issue = packedIssue(word);
  if (issue) {
    issues.push(issue);
    return null;
  }
  return { functionLengthBytes: ((word >>> 2) & 0x7ff) * 2, handlerRva: null,
    hasHandler: false, fragment: (word & 3) === 2, version: null };
};

const readXdataWord = async (reader: FileRangeReader, rvaToOff: RvaToOffset,
  rva: number, issues: string[]): Promise<number | null> => {
  const offset = rvaToOff(rva);
  if (offset == null || !Number.isSafeInteger(offset) || offset < 0 || offset >= reader.size) {
    issues.push("ARMNT .xdata RVA does not map to file data.");
    return null;
  }
  const word = await readWord(reader, rvaToOff, rva);
  if (word == null) {
    issues.push("ARMNT .xdata header is truncated.");
    return null;
  }
  return word;
};

const xdataRecordSize = (word: number, extension: number): number => {
  const extended = (word >>> 23) === 0;
  const scopes = extended ? extension & 0xffff : (word >>> 23) & 31;
  const codeWords = extended ? (extension >>> 16) & 255 : word >>> 28;
  return (extended ? 8 : 4) + ((word & (1 << 21)) === 0 ? scopes * 4 : 0) +
    codeWords * 4 + ((word & (1 << 20)) !== 0 ? 4 : 0);
};

const readXdataHeader = async (reader: FileRangeReader, rvaToOff: RvaToOffset, rva: number, issues: string[]) => {
  const word = await readXdataWord(reader, rvaToOff, rva, issues);
  if (word == null) return null;
  const extended = (word >>> 23) === 0;
  const extension = extended ? await readWord(reader, rvaToOff, rva + 4) : 0;
  if (extension == null) {
    issues.push("ARMNT .xdata extended header is truncated.");
    return null;
  }
  if (extended && (extension >>> 24) !== 0) issues.push("ARMNT .xdata extended header sets reserved bits.");
  const size = xdataRecordSize(word, extension);
  if (mappedRvaSize(rvaToOff, rva, size, reader.size) < size) {
    issues.push("ARMNT .xdata record is truncated before its unwind metadata ends.");
    return null;
  }
  return { word, size, extended, extension };
};

const readXdata = async (reader: FileRangeReader, rvaToOff: RvaToOffset,
  rva: number, issues: string[]): Promise<ArmntUnwindInfo | null> => {
  if (rva === 0) {
    issues.push("ARMNT .pdata entry points to .xdata RVA 0.");
    return null;
  }
  const header = await readXdataHeader(reader, rvaToOff, rva, issues);
  if (!header) return null;
  const hasHandler = (header.word & (1 << 20)) !== 0;
  const { extended, extension } = header;
  const scopeCount = extended ? extension & 0xffff : (header.word >>> 23) & 31;
  const codeWords = extended ? (extension >>> 16) & 255 : header.word >>> 28;
  const singleEpilogue = (header.word & (1 << 21)) !== 0;
  const codeRva = rva + (extended ? 8 : 4) + (singleEpilogue ? 0 : scopeCount * 4);
  const codeBytes = codeWords > 0 ? await readMappedRvaPrefix(reader, codeRva, codeWords * 4, rvaToOff) : null;
  const opcodes = codeBytes?.byteLength === codeWords * 4
    ? summarizeArmntOpcodeSequences(new Uint8Array(codeBytes.buffer, codeBytes.byteOffset, codeBytes.byteLength),
      await readSequenceStarts(reader, rvaToOff, { rva, headerWord: header.word, extension, extended,
        singleEpilogue, scopeCount, codeBytes: codeWords * 4, report: info => issues.push(info) }))
    : null;
  if (codeWords > 0 && !opcodes) issues.push("ARMNT .xdata unwind code pool is truncated.");
  if (opcodes && !opcodes.complete) issues.push("ARMNT .xdata unwind code sequence is incomplete or contains an unknown opcode.");
  const handlerRva = hasHandler ? await readWord(reader, rvaToOff, rva + header.size - 4) : null;
  if (hasHandler && handlerRva == null) {
    issues.push("ARMNT .xdata handler RVA is truncated.");
    return null;
  }
  if (hasHandler && handlerRva === 0) issues.push("ARMNT .xdata declares exception data with handler RVA 0.");
  const version = (header.word >>> 18) & 3;
  if (version !== 0) issues.push(`ARMNT .xdata has reserved version ${version}.`);
  return { functionLengthBytes: (header.word & 0x3ffff) * 2, handlerRva, hasHandler,
    ...(opcodes?.complete && issues.length === 0 ? languageHandler(rva, header.size, handlerRva) : {}),
    fragment: (header.word & (1 << 22)) !== 0, version, ...(opcodes ? { opcodes } : {}) };
};

interface ArmntSequenceLayout {
  rva: number;
  headerWord: number;
  extension: number;
  extended: boolean;
  singleEpilogue: boolean;
  scopeCount: number;
  codeBytes: number;
  report: (issue: string) => void;
}

const readSequenceStarts = async (reader: FileRangeReader, rvaToOff: RvaToOffset,
  layout: ArmntSequenceLayout): Promise<number[]> => {
  const { rva, headerWord, extension, extended, singleEpilogue, scopeCount, codeBytes, report } = layout;
  const starts: number[] = [];
  const fragment = (headerWord & (1 << 22)) !== 0;
  if (!fragment) starts.push(0);
  if (singleEpilogue) starts.push(extended ? (extension & 0xffff) : (headerWord >>> 23) & 31);
  else if (scopeCount > 0) {
    const scopeRva = rva + (extended ? 8 : 4);
    const scopeBytes = await readMappedRvaPrefix(reader, scopeRva, scopeCount * 4, rvaToOff);
    if (scopeBytes.byteLength !== scopeCount * 4) {
      report("ARMNT .xdata epilogue scope table is truncated.");
      return [];
    }
    const functionLength = headerWord & 0x3ffff;
    let previousOffset = -1;
    for (let scopeIndex = 0; scopeIndex < scopeCount; scopeIndex += 1) {
      const scopeWord = scopeBytes.getUint32(scopeIndex * 4, true);
      const offset = scopeWord & 0x3ffff;
      const start = scopeWord >>> 24;
      if (offset >= functionLength || offset <= previousOffset || (scopeWord & (3 << 18)) !== 0) {
        report("ARMNT .xdata epilogue scope has an invalid offset or reserved bits.");
        return [];
      }
      previousOffset = offset;
      starts.push(start);
    }
  }
  if (starts.some(start => start >= codeBytes)) {
    report("ARMNT .xdata sequence index exceeds its unwind code pool.");
    return [];
  }
  return starts;
};

/** Decode each shared .xdata or packed word once, including failed records. */
export const createArmntUnwindInfoReader = (reader: FileRangeReader, rvaToOff: RvaToOffset) => {
  const cache = new Map<number, { info: ArmntUnwindInfo | null; issues: string[] }>();
  return async (word: number, issues: string[]): Promise<ArmntUnwindInfo | null> => {
    const cached = cache.get(word);
    if (cached) {
      issues.push(...cached.issues);
      return cached.info;
    }
    const recordIssues: string[] = [];
    const flag = word & 3;
    if (flag === 3) recordIssues.push("ARMNT .pdata entry uses reserved unwind flag 3.");
    const info = flag === 3 ? null : flag === 0
      ? await readXdata(reader, rvaToOff, word, recordIssues) : readPacked(word, recordIssues);
    cache.set(word, { info, issues: recordIssues });
    issues.push(...recordIssues);
    return info;
  };
};
