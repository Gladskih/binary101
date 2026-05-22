"use strict";

import { isPrintableByte } from "../../../binary-utils.js";
import { loadIcedX86 } from "#iced-x86-loader";
import type { PeDosHeader, PeDosStubCode, PeDosStubInstruction } from "../types.js";
import { parseNestedPeAtDosEntrypoint } from "./dos-stub-nested-pe.js";
type DosStubPattern = "push-pop-then-dx" | "dx-then-push-pop";
type IcedInstruction = {
  code: number;
  length: number;
  ip: bigint;
  nextIP: bigint;
  flowControl: number;
  free(): void;
};
type IcedDecoder = {
  ip: bigint; canDecode: boolean; position: number;
  decodeOut(instruction: IcedInstruction): void; free(): void;
};
type IcedFormatter = { format(instruction: IcedInstruction): string; free(): void };
type DosStubIcedModule = {
  Code: Record<string, number>;
  Decoder: new (bitness: number, data: Uint8Array<ArrayBufferLike>, options: number) => IcedDecoder;
  DecoderOptions: { None: number };
  FlowControl: Record<string, number>;
  Formatter: new (syntax: number) => IcedFormatter;
  FormatterSyntax: { Nasm: number };
  Instruction: new () => IcedInstruction;
};
type IcedLoader = () => Promise<unknown>;

interface MatchResult {
  messageOffset: number;
  exitCode: number;
  instructions: PeDosStubInstruction[];
}

interface PreviewInstruction {
  publicInstruction: PeDosStubInstruction; code: number; length: number; nextOffset: number; flowControl: number;
}
const DOS_FIXED_HEADER_BYTES = 0x40;
const DOS_CODE_PREVIEW_LIMIT = 16;
// MS-DOS Encyclopedia, Section V: INT 21h AH=09h prints DS:DX until "$"; AH=4Ch exits.
// https://www.pcjs.org/documents/books/mspl13/msdos/encyclopedia/section5/
const DOS_PRINT_STRING_FUNCTION = 0x09;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;
const isDosStubIcedModule = (value: unknown): value is DosStubIcedModule => {
  if (!isRecord(value)) return false;
  const code = value["Code"];
  const decoderOptions = value["DecoderOptions"];
  const flowControl = value["FlowControl"];
  const formatterSyntax = value["FormatterSyntax"];
  return (
    isRecord(code) &&
    typeof code["INVALID"] === "number" &&
    isRecord(decoderOptions) &&
    typeof decoderOptions["None"] === "number" &&
    isRecord(flowControl) &&
    typeof flowControl["Next"] === "number" &&
    isRecord(formatterSyntax) &&
    typeof formatterSyntax["Nasm"] === "number" &&
    typeof value["Decoder"] === "function" &&
    typeof value["Formatter"] === "function" &&
    typeof value["Instruction"] === "function"
  );
};
const safeFree = (resource: { free(): void } | null | undefined): void => {
  if (!resource) return;
  try {
    resource.free();
  } catch {
    // iced-x86 cleanup is best-effort; parse results should survive partial WASM teardown.
  }
};
const unavailable = (notes: string[]): PeDosStubCode => ({ kind: "unavailable", instructions: [], notes });
const hex16 = (value: number): string => `0x${(value & 0xffff).toString(16).padStart(4, "0")}`;
const isDosMessageByte = (value: number): boolean =>
  isPrintableByte(value) || value === 0x09 || value === 0x0a || value === 0x0d;
const readDosMessage = (bytes: Uint8Array, offset: number): { text?: string; note?: string } => {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= bytes.length) {
    return { note: "DOS print string offset does not point inside the DOS load module." };
  }
  let text = "";
  for (let index = offset; index < bytes.length; index += 1) {
    const value = bytes[index];
    if (value === 0x24) return text ? { text } : { note: "DOS print string is empty." };
    if (value == null || !isDosMessageByte(value)) {
      return { note: "DOS print string contains non-printable bytes before the '$' terminator." };
    }
    text += String.fromCharCode(value);
  }
  return { note: "DOS print string is not '$'-terminated before the PE header." };
};
const readU16 = (bytes: Uint8Array, offset: number): number | null =>
  offset >= 0 && offset + 2 <= bytes.length ? bytes[offset]! | (bytes[offset + 1]! << 8) : null;
const instruction = (offset: number, text: string): PeDosStubInstruction => ({ offset, text });

const commonPatternInstructions = (
  pattern: DosStubPattern,
  dxOffset: number,
  exitCode: number
): PeDosStubInstruction[] =>
  pattern === "push-pop-then-dx" ? [
    instruction(0, "push cs"), instruction(1, "pop ds"), instruction(2, `mov dx,${hex16(dxOffset)}`),
    instruction(5, "mov ah,09h"), instruction(7, "int 21h"),
    instruction(9, `mov ax,${hex16(0x4c00 | exitCode)}`), instruction(12, "int 21h")
  ] : [
    instruction(0, `mov dx,${hex16(dxOffset)}`), instruction(3, "push cs"), instruction(4, "pop ds"),
    instruction(5, "mov ah,09h"), instruction(7, "int 21h"),
    instruction(9, `mov ax,${hex16(0x4c00 | exitCode)}`), instruction(12, "int 21h")
  ];

const matchCommonPattern = (
  bytes: Uint8Array,
  entryOffset: number,
  segmentBase: number,
  pattern: DosStubPattern
): MatchResult | null => {
  const dxOffset = readU16(bytes, entryOffset + (pattern === "push-pop-then-dx" ? 3 : 1));
  const exitCode = bytes[entryOffset + 10];
  const expected = pattern === "push-pop-then-dx"
    ? [0x0e, 0x1f, 0xba, null, null, 0xb4, DOS_PRINT_STRING_FUNCTION, 0xcd, 0x21, 0xb8, null, 0x4c, 0xcd, 0x21]
    : [0xba, null, null, 0x0e, 0x1f, 0xb4, DOS_PRINT_STRING_FUNCTION, 0xcd, 0x21, 0xb8, null, 0x4c, 0xcd, 0x21];
  if (dxOffset == null || exitCode == null || entryOffset + expected.length > bytes.length) return null;
  for (let index = 0; index < expected.length; index += 1) {
    const value = expected[index];
    if (value != null && bytes[entryOffset + index] !== value) return null;
  }
  return {
    messageOffset: segmentBase + dxOffset,
    exitCode,
    instructions: commonPatternInstructions(pattern, dxOffset, exitCode).map(item => ({
      offset: item.offset + entryOffset,
      text: item.text
    }))
  };
};

const buildStandardCode = (bytes: Uint8Array, match: MatchResult): PeDosStubCode => {
  const message = readDosMessage(bytes, match.messageOffset);
  if (!message.text) {
    return {
      kind: "custom-or-unrecognized",
      instructions: match.instructions,
      notes: [
        `Common DOS print-and-exit opcode pattern matched, but ${message.note ?? "message validation failed"}`
      ]
    };
  }
  return {
    kind: "standard-print-exit",
    messageOffset: match.messageOffset,
    message: message.text,
    exitCode: match.exitCode,
    instructions: match.instructions
  };
};

const appendNote = (code: PeDosStubCode, note: string): PeDosStubCode => ({
  ...code,
  notes: [...(code.notes ?? []), note]
});

const decodeAt = (
  decoder: IcedDecoder,
  formatter: IcedFormatter,
  instructionObject: IcedInstruction,
  offset: number
): PreviewInstruction | null => {
  if (!Number.isSafeInteger(offset) || offset < 0) return null;
  decoder.position = offset;
  decoder.ip = BigInt(offset);
  if (!decoder.canDecode) return null;
  decoder.decodeOut(instructionObject);
  const decodedOffset = Number(instructionObject.ip);
  const nextOffset = Number(instructionObject.nextIP);
  if (!Number.isSafeInteger(decodedOffset) || !Number.isSafeInteger(nextOffset)) return null;
  return {
    publicInstruction: { offset: decodedOffset, text: formatter.format(instructionObject) },
    code: instructionObject.code,
    length: instructionObject.length,
    nextOffset,
    flowControl: instructionObject.flowControl
  };
};

const loadDosStubIced = async (loader: IcedLoader): Promise<DosStubIcedModule | null> => {
  try {
    const module = await loader();
    return isDosStubIcedModule(module) ? module : null;
  } catch {
    return null;
  }
};

const previewUntilControlFlow = (
  iced: DosStubIcedModule,
  bytes: Uint8Array,
  entryOffset: number
): PeDosStubCode => {
  const decoder = new iced.Decoder(16, bytes, iced.DecoderOptions.None);
  const formatter = new iced.Formatter(iced.FormatterSyntax.Nasm);
  const instructionObject = new iced.Instruction();
  try {
    const instructions: PeDosStubInstruction[] = [];
    const notes = ["DOS stub code does not match the two common print-and-exit patterns."];
    let currentOffset = entryOffset;
    for (let index = 0; index < DOS_CODE_PREVIEW_LIMIT; index += 1) {
      const decoded = decodeAt(decoder, formatter, instructionObject, currentOffset);
      if (!decoded || decoded.length <= 0 || decoded.code === iced.Code["INVALID"]) {
        notes.push(`Preview stopped at invalid code near DOS load-module offset +0x${currentOffset.toString(16)}.`);
        break;
      }
      instructions.push(decoded.publicInstruction);
      if (decoded.flowControl !== iced.FlowControl["Next"]) {
        notes.push(`Preview stopped at control-flow instruction '${decoded.publicInstruction.text}'.`);
        break;
      }
      currentOffset = decoded.nextOffset;
    }
    if (instructions.length >= DOS_CODE_PREVIEW_LIMIT) {
      notes.push(`Preview capped at ${DOS_CODE_PREVIEW_LIMIT} instructions.`);
    }
    return { kind: "custom-or-unrecognized", instructions, notes };
  } finally {
    safeFree(instructionObject);
    safeFree(formatter);
    safeFree(decoder);
  }
};

const annotateMzEntrypoint = (code: PeDosStubCode, bytes: Uint8Array, entryOffset: number): PeDosStubCode =>
  bytes[entryOffset] === 0x4d && bytes[entryOffset + 1] === 0x5a // "MZ"
    ? { ...code, notes: [...(code.notes ?? []), "MZ entrypoint begins with another MZ signature."] }
    : code;

export const analyzePeDosStubCode = async (
  dos: Pick<PeDosHeader, "e_cparhdr" | "e_cs" | "e_ip">,
  stubBytesAfterFixedHeader: Uint8Array,
  peHeaderOffset: number,
  loader: IcedLoader = loadIcedX86
): Promise<PeDosStubCode> => {
  const dosHeaderBytes = dos.e_cparhdr * 16;
  if (dosHeaderBytes < DOS_FIXED_HEADER_BYTES) {
    const fixedHeaderFallback =
      matchCommonPattern(stubBytesAfterFixedHeader, 0, 0, "push-pop-then-dx") ||
      matchCommonPattern(stubBytesAfterFixedHeader, 0, 0, "dx-then-push-pop");
    if (fixedHeaderFallback) {
      return appendNote(
        buildStandardCode(stubBytesAfterFixedHeader, fixedHeaderFallback),
        "DOS header size is smaller than the fixed MZ header; code was recognized after the fixed header."
      );
    }
    return unavailable(["DOS header size is smaller than the fixed MZ header; code analysis skipped."]);
  }
  if (peHeaderOffset <= dosHeaderBytes) return unavailable(["DOS load module is empty before the PE header."]);
  // MZ header e_cs is a relocatable segment value, so load-module offsets use segment * 16 + offset.
  // https://wiki.osdev.org/MZ
  const segmentBase = dos.e_cs * 16;
  const entryOffset = segmentBase + dos.e_ip;
  const loadModuleOffset = dosHeaderBytes - DOS_FIXED_HEADER_BYTES;
  const loadModuleBytes = stubBytesAfterFixedHeader.subarray(loadModuleOffset);
  if (entryOffset < 0 || entryOffset >= loadModuleBytes.length) {
    return unavailable(["MZ entrypoint does not point inside the DOS load module."]);
  }
  const nestedPe = parseNestedPeAtDosEntrypoint(loadModuleBytes, entryOffset);
  if (nestedPe) {
    return {
      kind: "custom-or-unrecognized",
      instructions: [],
      nestedPe,
      notes: ["MZ entrypoint begins with a nested PE image instead of 16-bit DOS stub code."]
    };
  }
  const common =
    matchCommonPattern(loadModuleBytes, entryOffset, segmentBase, "push-pop-then-dx") ||
    matchCommonPattern(loadModuleBytes, entryOffset, segmentBase, "dx-then-push-pop");
  if (common) {
    return annotateMzEntrypoint(buildStandardCode(loadModuleBytes, common), loadModuleBytes, entryOffset);
  }
  const iced = await loadDosStubIced(loader);
  if (!iced) return unavailable(["16-bit DOS stub disassembler is not available."]);
  try {
    return annotateMzEntrypoint(
      previewUntilControlFlow(iced, loadModuleBytes, entryOffset),
      loadModuleBytes,
      entryOffset
    );
  } catch (error) {
    return unavailable([`16-bit DOS stub disassembly failed: ${String(error)}`]);
  }
};
