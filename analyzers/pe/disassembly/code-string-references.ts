"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { IcedInstructionObject, IcedX86Module } from "../../x86/disassembly-iced.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import type { RvaToOffset } from "../types.js";
import {
  peApiStringAddressToRva,
  type PeApiStringAddressCandidate,
  type PeApiStringDecoded
} from "./api-string-reference-model.js";
import {
  peApiStringReferenceKey,
  readPeApiStringCandidate
} from "./api-string-reader.js";
import { selectPeCodeStringReferences } from "./code-string-selection.js";
import type {
  PeApiStringEncoding,
  PeApiStringReference,
  PeCodeStringReference
} from "./types.js";

type PendingCodeStringReference = PeApiStringAddressCandidate & {
  instructionRvas: Set<number>;
};

type DecodedInstructionRange = {
  startRva: number;
  endRva: number;
};

export type PeCodeStringReferenceCollector = {
  record(instruction: IcedInstructionObject): void;
  references(
    reader: FileRangeReader,
    apiReferences?: readonly PeApiStringReference[]
  ): Promise<PeCodeStringReference[]>;
};

const CODE_STRING_ENCODINGS: readonly PeApiStringEncoding[] = ["ascii", "utf-16le"];
const MINIMUM_CODE_STRING_CHARS = 4;

const readImmediate = (
  instruction: IcedInstructionObject,
  operand: number
): bigint | null => {
  try {
    return BigInt.asUintN(64, instruction.immediate(operand));
  } catch {
    return null;
  }
};

const isDirectMemoryOperand = (
  iced: IcedX86Module,
  instruction: IcedInstructionObject,
  operand: number
): boolean => {
  if (instruction.opKind(operand) !== iced.OpKind["Memory"]) return false;
  const noRegister = iced.Register?.["None"];
  if (noRegister == null || instruction.memoryIndex !== noRegister) return false;
  const directAbsolute = instruction.memoryBase === noRegister;
  const ipRelativeBase =
    instruction.memoryBase === iced.Register?.["EIP"] ||
    instruction.memoryBase === iced.Register?.["RIP"];
  return (directAbsolute || ipRelativeBase) &&
    instruction.isIpRelMemoryOperand === ipRelativeBase;
};

const collectInstructionAddresses = (
  iced: IcedX86Module,
  instruction: IcedInstructionObject
): bigint[] => {
  const addresses = new Set<bigint>();
  for (let operand = 0; operand < instruction.opCount; operand += 1) {
    if (isDirectMemoryOperand(iced, instruction, operand)) {
      addresses.add(instruction.memoryDisplacement);
    }
    const immediate = readImmediate(instruction, operand);
    if (immediate != null) addresses.add(immediate);
  }
  return [...addresses.values()];
};

const candidateKey = (candidate: PeApiStringAddressCandidate): string =>
  `${candidate.address.toString(16)}:${candidate.encoding}`;

const addPendingReference = (
  references: Map<string, PendingCodeStringReference>,
  address: bigint,
  encoding: PeApiStringEncoding,
  instructionRva: number
): void => {
  const key = candidateKey({ address, encoding });
  const current = references.get(key);
  if (current) {
    current.instructionRvas.add(instructionRva);
    return;
  }
  references.set(key, { address, encoding, instructionRvas: new Set([instructionRva]) });
};

const addressMapsToFile = (
  address: bigint,
  imageBase: bigint,
  rvaToOff: RvaToOffset,
  headerRvaLimit: number
): boolean => {
  const rva = peApiStringAddressToRva(address, imageBase);
  if (rva != null && rva < headerRvaLimit) return false;
  const offset = rva == null ? null : rvaToOff(rva);
  return offset != null && offset >= 0;
};

const mergeReference = (
  references: Map<string, PeCodeStringReference>,
  decoded: PeApiStringDecoded,
  instructionRvas: Set<number>
): void => {
  const key = peApiStringReferenceKey(decoded);
  const current = references.get(key);
  const sortedInstructionRvas = sortInstructionRvas([...instructionRvas]);
  if (!current) {
    references.set(key, { ...decoded, instructionRvas: sortedInstructionRvas });
    return;
  }
  current.instructionRvas = mergeInstructionRvas(
    current.instructionRvas,
    sortedInstructionRvas
  );
};

const sortInstructionRvas = (rvas: number[]): number[] =>
  rvas.sort((left, right) => left - right);

const mergeInstructionRvas = (
  left: readonly number[],
  right: readonly number[]
): number[] => sortInstructionRvas([...new Set([...left, ...right])]);

const apiReferenceKeys = (
  references: readonly PeApiStringReference[]
): Set<string> => new Set(references.map(peApiStringReferenceKey));

const addDecodedInstructionRange = (
  ranges: DecodedInstructionRange[],
  instructionRva: number,
  length: number
): void => {
  if (!Number.isSafeInteger(length) || length <= 0) return;
  const endRva = instructionRva + length;
  if (endRva <= instructionRva || endRva > PE_RVA_EXCLUSIVE_LIMIT) return;
  ranges.push({ startRva: instructionRva, endRva });
};

const mergeDecodedInstructionRanges = (
  ranges: readonly DecodedInstructionRange[]
): DecodedInstructionRange[] => {
  const out: DecodedInstructionRange[] = [];
  const ordered = [...ranges].sort((left, right) =>
    left.startRva - right.startRva || left.endRva - right.endRva);
  for (const range of ordered) {
    const previous = out.at(-1);
    if (!previous || range.startRva > previous.endRva) {
      out.push({ ...range });
      continue;
    }
    previous.endRva = Math.max(previous.endRva, range.endRva);
  }
  return out;
};

const overlapsDecodedInstructions = (
  ranges: readonly DecodedInstructionRange[],
  rva: number,
  byteLength: number
): boolean => {
  const endRva = rva + byteLength;
  if (endRva <= rva || endRva > PE_RVA_EXCLUSIVE_LIMIT) return true;
  let low = 0;
  let high = ranges.length - 1;
  while (low <= high) {
    const index = Math.floor((low + high) / 2);
    const range = ranges[index];
    if (!range) return false;
    if (range.endRva <= rva) {
      low = index + 1;
    } else if (range.startRva >= endRva) {
      high = index - 1;
    } else {
      return true;
    }
  }
  return false;
};

const isUsefulCodeString = (decoded: PeApiStringDecoded): boolean =>
  [...decoded.text].length >= MINIMUM_CODE_STRING_CHARS &&
  [...decoded.text].every(character => {
    const codePoint = character.codePointAt(0) ?? 0;
    // Unicode permanently reserves U+FDD0..FDEF and every U+FFFE/U+FFFF plane tail
    // as noncharacters, which are strong evidence of decoded binary padding.
    return !(codePoint >= 0xfdd0 && codePoint <= 0xfdef) &&
      (codePoint & 0xfffe) !== 0xfffe;
  });

export const createPeCodeStringReferenceCollector = (
  iced: IcedX86Module,
  opts: {
    imageBase: bigint;
    headerRvaLimit?: number | undefined;
    rvaToOff: RvaToOffset;
  }
): PeCodeStringReferenceCollector => {
  const pending = new Map<string, PendingCodeStringReference>();
  const decodedInstructionRanges: DecodedInstructionRange[] = [];
  const headerRvaLimit =
    Number.isSafeInteger(opts.headerRvaLimit) && (opts.headerRvaLimit ?? 0) > 0
      ? (opts.headerRvaLimit ?? 0) >>> 0
      : 0;
  return {
    record: (instruction: IcedInstructionObject): void => {
      const instructionRva = peApiStringAddressToRva(instruction.ip, opts.imageBase);
      if (instructionRva == null) return;
      addDecodedInstructionRange(decodedInstructionRanges, instructionRva, instruction.length);
      for (const address of collectInstructionAddresses(iced, instruction)) {
        if (!addressMapsToFile(address, opts.imageBase, opts.rvaToOff, headerRvaLimit)) continue;
        CODE_STRING_ENCODINGS.forEach(encoding =>
          addPendingReference(pending, address, encoding, instructionRva));
      }
    },
    references: async (reader, apiReferences = []) => {
      const references = new Map<string, PeCodeStringReference>();
      const apiKeys = apiReferenceKeys(apiReferences);
      const codeRanges = mergeDecodedInstructionRanges(decodedInstructionRanges);
      for (const candidate of pending.values()) {
        const decoded = await readPeApiStringCandidate(
          reader,
          opts.rvaToOff,
          opts.imageBase,
          candidate,
          { headerRvaLimit }
        );
        if (
          decoded &&
          isUsefulCodeString(decoded) &&
          (
            // Keep API-confirmed strings in the complete table; any overlap with decoded
            // instruction bytes is a disassembly diagnostic, not a reason to hide the API fact.
            apiKeys.has(peApiStringReferenceKey(decoded)) ||
            !overlapsDecodedInstructions(codeRanges, decoded.rva, decoded.byteLength)
          )
        ) {
          mergeReference(references, decoded, candidate.instructionRvas);
        }
      }
      return selectPeCodeStringReferences([...references.values()], apiReferences);
    }
  };
};
