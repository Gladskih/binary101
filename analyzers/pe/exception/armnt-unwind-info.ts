import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { mappedRvaSize } from "../rva-mapping.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";

// ARMNT differs from ARM64: lengths use 2-byte units, F occupies bit22,
// Epilogue Count starts at bit23, and Code Words occupies bits28..31.
// https://learn.microsoft.com/en-us/cpp/build/arm-exception-handling
export interface ArmntUnwindInfo {
  functionLengthBytes: number;
  handlerRva: number | null;
  hasHandler: boolean;
  fragment: boolean;
  version: number | null;
}

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
  return { word, size };
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
  const handlerRva = hasHandler ? await readWord(reader, rvaToOff, rva + header.size - 4) : null;
  if (hasHandler && handlerRva == null) {
    issues.push("ARMNT .xdata handler RVA is truncated.");
    return null;
  }
  if (hasHandler && handlerRva === 0) issues.push("ARMNT .xdata declares exception data with handler RVA 0.");
  const version = (header.word >>> 18) & 3;
  if (version !== 0) issues.push(`ARMNT .xdata has reserved version ${version}.`);
  return { functionLengthBytes: (header.word & 0x3ffff) * 2, handlerRva, hasHandler,
    fragment: (header.word & (1 << 22)) !== 0, version };
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
