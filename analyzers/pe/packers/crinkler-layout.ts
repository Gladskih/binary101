import {
  COFF_FILE_HEADER_BYTE_LENGTH, COFF_FILE_HEADER_FIELDS, readCoffField
} from "../../coff/layout.js";
import { IMAGE_FILE_MACHINE_I386 } from "../../coff/machine.js";
import { PE32_OPTIONAL_HEADER_MAGIC } from "../optional-header/magic.js";
import { hasPeSignature, PE_SIGNATURE_BYTE_LENGTH, peProbe } from "../security/signature.js";
import type { CrinklerTinyModel } from "./crinkler-tiny-codec.js";

// PE32 field offsets are relative to IMAGE_OPTIONAL_HEADER32.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
const pe32 = { entry: 16, imageBase: 28, fileAlignment: 36, imageSize: 56, headerSize: 60 };
const coffStart = (pe: number): number => pe + PE_SIGNATURE_BYTE_LENGTH;
const optionalStart = (pe: number): number => coffStart(pe) + COFF_FILE_HEADER_BYTE_LENGTH;

// Recompress recognizes e_lfanew 4 and 12, reads the two producer digits, and searches
// the first 0x200 bytes for the relocated bit-test and model instructions.
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/Crinkler.cpp
export const CRINKLER_SHORT_OPTIONAL_HEADER_BYTES = 8;
const compact = { pe: 4, version: 2 };
const compatibility = { pe: 12, version: 38, originalOptionalSize: 0x78 };

// Fixed file offsets in DepackInit and AritDecodeLoop. The operands of mov esi/edi
// and bt contain the relocated model, output and packed-data addresses.
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/modules/header30.asm
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/modules/old/header20.asm
const standardStub = { entry: 0x5c, modelsInstruction: 0x65, bitTest: 0x44 };
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/modules/header22_1k.asm
const tinyStub = { entry: 0x64, returnInstruction: 0x5f, bitTest: 0x0c };
// The 1.3 one-section layout maps DepackInit at RVA 0x10002 and file offset 2.
// Later compatibility headers start with a short jump to that same file offset.
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/modules/old/header13.asm
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/modules/header30_compatibility.asm
const compatibilityStub = {
  init: 2, sectionEntry: 0x10002, jumpEntry: 0x52, modelsInstruction: 0x6d, bitTestSearch: 0x94
};
const packedBitTest = [0x0f, 0xa3, 0x2d]; // bt dword [absolute address], ebp

export interface CrinklerLayout {
  profile: "standard" | "compatibility" | "tiny";
  version: string;
  imageBase: number;
  entryRva: number;
  entryOffset: number;
  imageSize: number;
  headerSize: number;
  unpackedVa: number;
  streamOffset: number;
  modelOffset?: number;
}

export interface CrinklerTinyLayout {
  size: number;
  model: CrinklerTinyModel;
}

const at = (bytes: Uint8Array, offset: number, signature: readonly number[]): boolean =>
  signature.every((value, index) => bytes[offset + index] === value);

const find = (
  bytes: Uint8Array, start: number, end: number, signature: readonly number[]
): number => {
  for (let offset = start; offset + signature.length <= end; offset += 1) {
    if (at(bytes, offset, signature)) return offset;
  }
  return -1;
};

const versionAt = (bytes: Uint8Array, offset: number): string | null => {
  // Supported version markers follow the header families in the release history.
  // https://github.com/runestubbe/Crinkler/blob/f74d964/doc/manual.txt
  const marker = String.fromCharCode(...bytes.subarray(offset, offset + 2));
  return /^(?:1[34]|2[0-3]|30)$/.test(marker) ? `${marker[0]}.${marker[1]}` : null;
};

const tinyAnchors = (bytes: Uint8Array, entry: number) => {
  // Tiny DepackInit starts with push ebx / mov edi, imm32. The exit pad ends in ret.
  if (entry === tinyStub.entry && at(bytes, entry, [0x53, 0xbf]) &&
      bytes[tinyStub.returnInstruction] === 0xc3) {
    return { profile: "tiny" as const, entry, bitTest: tinyStub.bitTest, output: entry + 2 };
  }
  return null;
};

const standardAnchors = (bytes: Uint8Array, entry: number) => {
  if (entry !== standardStub.entry || bytes[entry] !== 0x53 ||
      bytes[standardStub.modelsInstruction] !== 0xbe) return null;
  // mov esi, _Models is followed by mov edi, _UnpackedData (or push 1 / pop eax first).
  const nextInstruction = standardStub.modelsInstruction + 1 + Uint32Array.BYTES_PER_ELEMENT;
  const outputOpcode = nextInstruction + (at(bytes, nextInstruction, [0x6a, 0x01, 0x58]) ? 3 : 0);
  return bytes[outputOpcode] === 0xbf
    ? { profile: "standard" as const, entry, bitTest: standardStub.bitTest, output: outputOpcode + 1 }
    : null;
};

const compactAnchors = (bytes: Uint8Array, view: DataView) => {
  // Both compact templates place the PE header at 4 and declare FileAlignment = 4.
  const optional = optionalStart(compact.pe);
  if (view.getUint32(optional + pe32.fileAlignment, true) !== compact.pe) return null;
  const entry = view.getUint32(optional + pe32.entry, true);
  return tinyAnchors(bytes, entry) ?? standardAnchors(bytes, entry);
};

const hasCompatibilityInit = (bytes: Uint8Array): boolean => {
  const { init, modelsInstruction } = compatibilityStub;
  // DepackInit: mov edi, imm32 / push edi / xor eax, eax / jmp rel8.
  // DepackInit2: mov esi, imm32 / push 0 / pop ecx / jmp rel32.
  return bytes[init] === 0xbf && at(bytes, init + 5, [0x57, 0x31, 0xc0, 0xeb]) &&
    bytes[modelsInstruction] === 0xbe &&
    at(bytes, modelsInstruction + 5, [0x6a, 0x00, 0x59, 0xe9]);
};

const compatibilityAnchors = (bytes: Uint8Array, view: DataView) => {
  const entry = view.getUint32(optionalStart(compatibility.pe) + pe32.entry, true);
  const { init, sectionEntry, jumpEntry, bitTestSearch } = compatibilityStub;
  if (!hasCompatibilityInit(bytes)) return null;
  if (entry !== sectionEntry && !(entry === jumpEntry && bytes[entry] === 0xeb)) return null;
  return {
    profile: "compatibility" as const,
    entry,
    output: init + 1,
    bitTest: find(bytes, bitTestSearch, bytes.length, packedBitTest)
  };
};

const validPeShape = (view: DataView, pe: number): boolean => {
  if (!hasPeSignature(view, pe)) return false;
  const coff = coffStart(pe);
  const fields = COFF_FILE_HEADER_FIELDS;
  if (readCoffField(view, coff, fields.Machine) !== IMAGE_FILE_MACHINE_I386) return false;
  if (view.getUint16(optionalStart(pe), true) !== PE32_OPTIONAL_HEADER_MAGIC) return false;
  const sections = readCoffField(view, coff, fields.NumberOfSections);
  const optionalSize = readCoffField(view, coff, fields.SizeOfOptionalHeader);
  return (sections === 0 && optionalSize === CRINKLER_SHORT_OPTIONAL_HEADER_BYTES) ||
    (pe === compatibility.pe && sections === 1 && optionalSize === compatibility.originalOptionalSize);
};

const readCrinklerHeader = (view: DataView) => {
  const pe = peProbe(view)?.e_lfanew;
  return [compact, compatibility].find(header => header.pe === pe && validPeShape(view, pe));
};

export const readCrinklerLayout = (bytes: Uint8Array): CrinklerLayout | null => {
  // DepackInit2 has a 13-byte mov/push/pop/jmp sequence after the fixed header fields.
  if (bytes.length < compatibilityStub.modelsInstruction + 13) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const header = readCrinklerHeader(view);
  if (!header) return null;
  const { pe } = header;
  const version = versionAt(bytes, header.version);
  const anchors = pe === compact.pe ? compactAnchors(bytes, view) : compatibilityAnchors(bytes, view);
  if (!version || !anchors || !hasPackedOperand(bytes, anchors.bitTest)) return null;
  return readLayoutFields(view, pe, version, anchors);
};

const packedOperandEnd = (bitTest: number): number =>
  bitTest + packedBitTest.length + Uint32Array.BYTES_PER_ELEMENT;
const hasPackedOperand = (bytes: Uint8Array, bitTest: number): boolean =>
  bitTest >= 0 && packedOperandEnd(bitTest) <= bytes.length && at(bytes, bitTest, packedBitTest);

type LayoutAnchors = NonNullable<ReturnType<typeof compactAnchors | typeof compatibilityAnchors>>;

const readModelOffset = (view: DataView, anchors: LayoutAnchors, imageBase: number): number => {
  const modelsInstruction = anchors.profile === "standard"
    ? standardStub.modelsInstruction : compatibilityStub.modelsInstruction;
  return view.getUint32(modelsInstruction + 1, true) - imageBase;
};

const readPackedFields = (view: DataView, anchors: LayoutAnchors, imageBase: number) => {
  const unpackedVa = view.getUint32(anchors.output, true);
  const streamOffset = view.getUint32(anchors.bitTest + packedBitTest.length, true) - imageBase;
  if (!imageBase || unpackedVa <= imageBase || streamOffset <= packedOperandEnd(anchors.bitTest)) {
    return null;
  }
  if (anchors.profile === "tiny") return { unpackedVa, streamOffset };
  const modelOffset = readModelOffset(view, anchors, imageBase);
  return modelOffset > anchors.bitTest && modelOffset < streamOffset
    ? { unpackedVa, streamOffset, modelOffset } : null;
};

const readLayoutFields = (
  view: DataView, pe: number, version: string, anchors: LayoutAnchors
): CrinklerLayout | null => {
  if (anchors.profile === "tiny" && version.startsWith("1.")) return null;
  const optional = optionalStart(pe);
  const imageBase = view.getUint32(optional + pe32.imageBase, true);
  const packed = readPackedFields(view, anchors, imageBase);
  if (!packed) return null;
  return {
    profile: anchors.profile, version, imageBase, ...packed,
    entryRva: anchors.entry,
    entryOffset: anchors.entry === compatibilityStub.sectionEntry ? compatibilityStub.init : anchors.entry,
    imageSize: view.getUint32(optional + pe32.imageSize, true),
    headerSize: view.getUint32(optional + pe32.headerSize, true)
  };
};

const tinyModelOffsets = (bytes: Uint8Array) => {
  // Recompress locates the base weights and mask by instructions leading into model_loop.
  // https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/Crinkler.cpp
  // In 2.0/2.1, mov ecx,0 / pop ecx is followed by two push imm8 and mov edx,imm32.
  if (at(bytes, 0x77, [0xb9, 0, 0, 0, 0, 0x59, 0x6a])) {
    return { one: 0x7e, zero: 0x80, mask: 0x82 };
  }
  // From 2.2, cmp eax,0 separates the two push imm8 instructions.
  if (bytes[0x75] === 0x6a && at(bytes, 0x77, [0x3d, 0, 0, 0, 0, 0x6a])) {
    return { one: 0x76, zero: 0x7d, mask: 0x7f };
  }
  return null;
};

export const readCrinklerTinyLayout = (
  bytes: Uint8Array, layout: CrinklerLayout
): CrinklerTinyLayout | null => {
  const model = tinyModelOffsets(bytes);
  const end = Math.min(layout.streamOffset, bytes.length);
  // DepackEndPositionP follows cmp di,imm16 at the end of the model loop.
  // BoostFactorPtrP follows mov cl,imm8 immediately before mov esi,esp.
  // https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/modules/header22_1k.asm
  const compareEnd = [0x66, 0x81, 0xff];
  const endComparison = find(bytes, 0xc0, end, compareEnd);
  if (!model || endComparison < 0) return null;
  const sizeOffset = endComparison + compareEnd.length;
  if (sizeOffset + Uint16Array.BYTES_PER_ELEMENT > end) return null;
  // These bounds cover the boost sequence in the supported 2.0–3.0 Tiny Header layouts.
  const stackCopy = find(bytes, 0xa1, Math.min(end, 0xb0), [0x89, 0xe6]);
  if (stackCopy < 0 || bytes[stackCopy - 2] !== 0xb1) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    size: view.getUint16(sizeOffset, true),
    model: {
      baseOne: bytes[model.one]!, baseZero: bytes[model.zero]!,
      mask: view.getUint32(model.mask, true), boost: bytes[stackCopy - 1]!
    }
  };
};
