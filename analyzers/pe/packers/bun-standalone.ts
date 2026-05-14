"use strict";

import { peSectionNameValue } from "../sections/name.js";
import type {
  BunStandaloneDetectorInput,
  PePackerDetectorResult,
  PePackerDetail,
  PePackerFinding
} from "./types.js";

type BunImagePointerBytes = BunStandaloneDetectorInput["imagePointerBytes"];

interface BunOffsetsLayout {
  imagePointerBytes: BunImagePointerBytes;
  offsetsSize: number;
  modulesPointerOffset: number;
  entryPointIdOffset: number;
  compileArgvPointerOffset: number;
  flagsOffset: number;
}

interface BunPayloadCandidate {
  payloadStart: number;
  payloadEnd: number;
  payloadSize: number;
  storage: string;
}

type BunPayloadReadResult = { candidate: BunPayloadCandidate | null; warnings: string[] };
type BunPayloadSizeReadResult = { payloadSize: number } | { warning: string };
type BunPayloadBuildResult = { payload: BunPayloadCandidate } | { warning: string };

// Bun StandaloneModuleGraph appends this trailer after the serialized graph offsets.
// https://github.com/oven-sh/bun/blob/main/src/standalone_graph/StandaloneModuleGraph.zig
const BUN_TRAILER_BYTES = new TextEncoder().encode("\n---- Bun! ----\n");
const BUN_SECTION_NAME = ".bun";
const BUN_SECTION_LENGTH_BYTES = BigUint64Array.BYTES_PER_ELEMENT;
const BUN_STRING_POINTER_BYTES = Uint32Array.BYTES_PER_ELEMENT * 2;
const BUN_ENTRY_POINT_ID_BYTES = Uint32Array.BYTES_PER_ELEMENT;
const BUN_FLAGS_BYTES = Uint32Array.BYTES_PER_ELEMENT;
// Bun Offsets stores usize byte_count, two StringPointers, entry_point_id, and flags before the trailer.
// Flags are currently the low four compile option bits.
// https://github.com/oven-sh/bun/blob/main/src/standalone_graph/StandaloneModuleGraph.zig
const BUN_FLAG_LABELS = [
  "disable default env files",
  "disable autoload bunfig",
  "disable autoload tsconfig",
  "disable autoload package.json"
];
const BUN_KNOWN_FLAGS_MASK = (1 << BUN_FLAG_LABELS.length) - 1;

const hasBytes = (readerSize: number, offset: number, size: number): boolean =>
  Number.isSafeInteger(offset) &&
  Number.isSafeInteger(size) &&
  offset >= 0 &&
  size >= 0 &&
  offset <= readerSize &&
  size <= readerSize - offset;

const readPayloadLength = (view: DataView): bigint | null =>
  view.byteLength >= BUN_SECTION_LENGTH_BYTES ? view.getBigUint64(0, true) : null;

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
};

const readStringPointer = (view: DataView, offset: number): { offset: number; length: number } => ({
  offset: view.getUint32(offset, true),
  length: view.getUint32(offset + Uint32Array.BYTES_PER_ELEMENT, true)
});

const stringPointerFits = (
  pointer: { offset: number; length: number },
  byteCount: number
): boolean =>
  pointer.offset <= byteCount && pointer.length <= byteCount - pointer.offset;

const decodeBunFlags = (flags: number): string =>
  BUN_FLAG_LABELS
    .filter((_, index) => (flags & (1 << index)) !== 0)
    .join(", ") || "none";

const createBunOffsetsLayout = (imagePointerBytes: BunImagePointerBytes): BunOffsetsLayout => {
  const modulesPointerOffset = imagePointerBytes;
  const entryPointIdOffset = modulesPointerOffset + BUN_STRING_POINTER_BYTES;
  const compileArgvPointerOffset = entryPointIdOffset + BUN_ENTRY_POINT_ID_BYTES;
  const flagsOffset = compileArgvPointerOffset + BUN_STRING_POINTER_BYTES;
  return {
    imagePointerBytes,
    offsetsSize: flagsOffset + BUN_FLAGS_BYTES,
    modulesPointerOffset,
    entryPointIdOffset,
    compileArgvPointerOffset,
    flagsOffset
  };
};

const readByteCount = (view: DataView, layout: BunOffsetsLayout): bigint =>
  layout.imagePointerBytes === BigUint64Array.BYTES_PER_ELEMENT
    ? view.getBigUint64(0, true)
    : BigInt(view.getUint32(0, true));

const meaningfulSectionSize = (sectionSize: number, virtualSize: number): number =>
  virtualSize > 0 && virtualSize <= sectionSize ? virtualSize : sectionSize;

const rejectPayload = (warning: string): BunPayloadReadResult => ({
  candidate: null,
  warnings: [warning]
});

const readTrailerMatches = async (
  input: BunStandaloneDetectorInput,
  payloadEnd: number
): Promise<boolean> => {
  const trailerOffset = payloadEnd - BUN_TRAILER_BYTES.byteLength;
  const trailerBytes = await input.reader.readBytes(trailerOffset, BUN_TRAILER_BYTES.byteLength);
  return bytesEqual(trailerBytes, BUN_TRAILER_BYTES);
};

const readLengthPrefixedPayloadSize = async (
  input: BunStandaloneDetectorInput,
  sectionStart: number,
  sectionSize: number
): Promise<BunPayloadSizeReadResult> => {
  if (sectionSize < BUN_SECTION_LENGTH_BYTES) {
    return { warning: "Bun .bun section is truncated before its 8-byte payload length." };
  }
  if (!hasBytes(input.reader.size, sectionStart, BUN_SECTION_LENGTH_BYTES)) {
    return { warning: "Bun .bun section raw data starts outside the file." };
  }
  const lengthView = await input.reader.read(sectionStart, BUN_SECTION_LENGTH_BYTES);
  const payloadSize = readPayloadLength(lengthView);
  if (payloadSize == null) {
    return { warning: "Bun .bun section is truncated before its 8-byte payload length." };
  }
  if (payloadSize > BigInt(Number.MAX_SAFE_INTEGER)) {
    return { warning: "Bun .bun payload length exceeds Number.MAX_SAFE_INTEGER." };
  }
  return { payloadSize: Number(payloadSize) };
};

const buildLengthPrefixedPayload = (
  input: BunStandaloneDetectorInput,
  sectionStart: number,
  sectionSize: number,
  payloadSize: number
): BunPayloadBuildResult => {
  const payloadStart = sectionStart + BUN_SECTION_LENGTH_BYTES;
  const payloadEnd = payloadStart + payloadSize;
  if (!Number.isSafeInteger(payloadEnd)) {
    return { warning: "Bun .bun declared payload range exceeds Number.MAX_SAFE_INTEGER." };
  }
  if (payloadSize < BUN_TRAILER_BYTES.byteLength) {
    return { warning: "Bun .bun payload is too small to contain the Bun trailer." };
  }
  if (
    payloadSize > sectionSize - BUN_SECTION_LENGTH_BYTES ||
    !hasBytes(input.reader.size, payloadStart, payloadSize)
  ) {
    return { warning: "Bun .bun declared payload length extends past the section or EOF." };
  }
  return { payload: { payloadStart, payloadEnd, payloadSize, storage: "length-prefixed PE section" } };
};

const readLengthPrefixedPayload = async (
  input: BunStandaloneDetectorInput,
  sectionStart: number,
  sectionSize: number
): Promise<BunPayloadReadResult> => {
  const sizeResult = await readLengthPrefixedPayloadSize(input, sectionStart, sectionSize);
  if ("warning" in sizeResult) return rejectPayload(sizeResult.warning);
  const buildResult = buildLengthPrefixedPayload(input, sectionStart, sectionSize, sizeResult.payloadSize);
  if ("warning" in buildResult) return rejectPayload(buildResult.warning);
  if (await readTrailerMatches(input, buildResult.payload.payloadEnd)) {
    return { candidate: buildResult.payload, warnings: [] };
  }
  return rejectPayload("Bun .bun payload is missing the expected standalone module-graph trailer.");
};

const readDirectPayload = async (
  input: BunStandaloneDetectorInput,
  sectionStart: number,
  sectionSize: number,
  virtualSize: number
): Promise<BunPayloadCandidate | null> => {
  const payloadSize = meaningfulSectionSize(sectionSize, virtualSize);
  if (
    payloadSize < BUN_TRAILER_BYTES.byteLength ||
    !hasBytes(input.reader.size, sectionStart, payloadSize)
  ) {
    return null;
  }
  const payloadEnd = sectionStart + payloadSize;
  if (!(await readTrailerMatches(input, payloadEnd))) return null;
  return { payloadStart: sectionStart, payloadEnd, payloadSize, storage: "PE section virtual data" };
};

const appendOffsetDetails = (
  view: DataView,
  layout: BunOffsetsLayout,
  payloadSize: number,
  details: PePackerDetail[],
  warnings: string[]
): void => {
  const byteCount = readByteCount(view, layout);
  if (byteCount > BigInt(Number.MAX_SAFE_INTEGER)) {
    warnings.push("Bun .bun offsets byte_count exceeds Number.MAX_SAFE_INTEGER.");
    return;
  }
  const byteCountNumber = Number(byteCount);
  const modulesPointer = readStringPointer(view, layout.modulesPointerOffset);
  const compileArgvPointer = readStringPointer(view, layout.compileArgvPointerOffset);
  if (byteCountNumber > payloadSize) warnings.push("Bun .bun offsets byte_count points past the payload.");
  if (!stringPointerFits(modulesPointer, byteCountNumber)) {
    warnings.push("Bun .bun module-list pointer is outside byte_count.");
  }
  if (!stringPointerFits(compileArgvPointer, byteCountNumber)) {
    warnings.push("Bun .bun compile argv pointer is outside byte_count.");
  }
  const flags = view.getUint32(layout.flagsOffset, true);
  if ((flags & ~BUN_KNOWN_FLAGS_MASK) !== 0) warnings.push("Bun .bun flags contain non-zero reserved bits.");
  details.push(
    { label: "Graph byte_count", kind: "bytes", value: byteCountNumber },
    {
      label: "Entry point id",
      kind: "number",
      value: view.getUint32(layout.entryPointIdOffset, true)
    },
    { label: "Module-list bytes", kind: "bytes", value: modulesPointer.length },
    { label: "Compile argv bytes", kind: "bytes", value: compileArgvPointer.length },
    { label: "Flags", kind: "text", value: decodeBunFlags(flags) }
  );
};

const readBunOffsetDetails = async (
  input: BunStandaloneDetectorInput,
  payloadEnd: number,
  payloadSize: number,
  details: PePackerDetail[],
  warnings: string[]
): Promise<void> => {
  const layout = createBunOffsetsLayout(input.imagePointerBytes);
  const offsetsStart = payloadEnd - BUN_TRAILER_BYTES.byteLength - layout.offsetsSize;
  if (offsetsStart < 0 || payloadSize < layout.offsetsSize + BUN_TRAILER_BYTES.byteLength) {
    warnings.push("Bun .bun payload is too small to contain offsets before the trailer.");
    return;
  }
  const view = await input.reader.read(offsetsStart, layout.offsetsSize);
  if (view.byteLength < layout.offsetsSize) {
    warnings.push("Bun .bun offsets are truncated by EOF.");
    return;
  }
  appendOffsetDetails(view, layout, payloadSize, details, warnings);
};

const createBunFinding = (
  sectionStart: number,
  sectionEnd: number,
  payload: BunPayloadCandidate,
  details: PePackerDetail[]
): PePackerFinding => ({
  id: "bun-standalone",
  name: "Bun standalone executable",
  kind: "runtime-packager",
  confidence: "high",
  evidence: [
    "PE section table contains a .bun section.",
    "The .bun payload has Bun's standalone module-graph trailer."
  ],
  details: [
    { label: ".bun raw range", kind: "range", start: sectionStart, end: sectionEnd },
    { label: "Payload range", kind: "range", start: payload.payloadStart, end: payload.payloadEnd },
    { label: "Storage", kind: "text", value: payload.storage },
    ...details
  ]
});

export const detectBunStandalone = async (
  input: BunStandaloneDetectorInput
): Promise<PePackerDetectorResult> => {
  const findings: PePackerFinding[] = [];
  const warnings: string[] = [];
  const bunSections = input.sections.filter(section => peSectionNameValue(section.name) === BUN_SECTION_NAME);
  for (const section of bunSections) {
    const sectionStart = section.pointerToRawData >>> 0;
    const sectionSize = section.sizeOfRawData >>> 0;
    const prefixed = await readLengthPrefixedPayload(input, sectionStart, sectionSize);
    const payload = prefixed.candidate ??
      (await readDirectPayload(input, sectionStart, sectionSize, section.virtualSize));
    if (!payload) {
      warnings.push(...prefixed.warnings);
      continue;
    }
    const details: PePackerDetail[] = [];
    await readBunOffsetDetails(input, payload.payloadEnd, payload.payloadSize, details, warnings);
    findings.push(createBunFinding(sectionStart, sectionStart + sectionSize, payload, details));
  }
  return { findings, warnings };
};
