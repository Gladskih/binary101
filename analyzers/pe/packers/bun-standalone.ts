"use strict";

import { peSectionNameValue } from "../sections/name.js";
import {
  BUN_TRAILER_BYTES,
  readBunPayload,
  type BunPayloadCandidate
} from "./bun-payload.js";
import type {
  BunOffsetMetadata,
  BunStandaloneDetectorInput,
  PeBunPackerFinding,
  PePackerDetectorResult
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

const BUN_SECTION_NAME = ".bun";
const BUN_STRING_POINTER_BYTES = Uint32Array.BYTES_PER_ELEMENT * 2;
const BUN_ENTRY_POINT_ID_BYTES = Uint32Array.BYTES_PER_ELEMENT;
const BUN_FLAGS_BYTES = Uint32Array.BYTES_PER_ELEMENT;
// Bun Offsets stores usize byte_count, two StringPointers, entry_point_id, and flags before the trailer.
// Flags are currently the low four compile option bits.
// https://github.com/oven-sh/bun/blob/main/src/standalone_graph/StandaloneModuleGraph.zig
const BUN_KNOWN_FLAGS_MASK = 0x0f;

const readStringPointer = (view: DataView, offset: number): { offset: number; length: number } => ({
  offset: view.getUint32(offset, true),
  length: view.getUint32(offset + Uint32Array.BYTES_PER_ELEMENT, true)
});

const stringPointerFits = (
  pointer: { offset: number; length: number },
  byteCount: number
): boolean =>
  pointer.offset <= byteCount && pointer.length <= byteCount - pointer.offset;

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

const parseOffsetMetadata = (
  view: DataView,
  layout: BunOffsetsLayout,
  payloadSize: number,
  warnings: string[]
): BunOffsetMetadata | null => {
  const byteCount = readByteCount(view, layout);
  if (byteCount > BigInt(Number.MAX_SAFE_INTEGER)) {
    warnings.push("Bun .bun offsets byte_count exceeds Number.MAX_SAFE_INTEGER.");
    return null;
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
  return {
    byteCount: byteCountNumber,
    compileArgvBytes: compileArgvPointer.length,
    entryPointId: view.getUint32(layout.entryPointIdOffset, true),
    flags,
    moduleListBytes: modulesPointer.length
  };
};

const readBunOffsetMetadata = async (
  input: BunStandaloneDetectorInput,
  payloadEnd: number,
  payloadSize: number,
  warnings: string[]
): Promise<BunOffsetMetadata | null> => {
  const layout = createBunOffsetsLayout(input.imagePointerBytes);
  const offsetsStart = payloadEnd - BUN_TRAILER_BYTES.byteLength - layout.offsetsSize;
  if (offsetsStart < 0 || payloadSize < layout.offsetsSize + BUN_TRAILER_BYTES.byteLength) {
    warnings.push("Bun .bun payload is too small to contain offsets before the trailer.");
    return null;
  }
  const view = await input.reader.read(offsetsStart, layout.offsetsSize);
  if (view.byteLength < layout.offsetsSize) {
    warnings.push("Bun .bun offsets are truncated by EOF.");
    return null;
  }
  return parseOffsetMetadata(view, layout, payloadSize, warnings);
};

const createBunFinding = (
  sectionStart: number,
  sectionSize: number,
  payload: BunPayloadCandidate,
  offsetMetadata: BunOffsetMetadata | null
): PeBunPackerFinding => ({
  id: "bun-standalone",
  name: "Bun standalone executable",
  kind: "runtime-packager",
  confidence: "high",
  evidence: [
    "PE section table contains a .bun section.",
    "The .bun payload has Bun's standalone module-graph trailer."
  ],
  sectionStart,
  sectionSize,
  payloadStart: payload.payloadStart,
  payloadSize: payload.payloadSize,
  storage: payload.storage,
  ...(offsetMetadata ? { offsetMetadata } : {})
});

export const detectBunStandalone = async (
  input: BunStandaloneDetectorInput
): Promise<PePackerDetectorResult<PeBunPackerFinding>> => {
  const findings: PeBunPackerFinding[] = [];
  const warnings: string[] = [];
  const bunSections = input.sections.filter(section => peSectionNameValue(section.name) === BUN_SECTION_NAME);
  for (const section of bunSections) {
    const sectionStart = section.pointerToRawData >>> 0;
    const sectionSize = section.sizeOfRawData >>> 0;
    const payloadResult = await readBunPayload(input, sectionStart, sectionSize, section.virtualSize);
    if (!payloadResult.candidate) {
      warnings.push(...payloadResult.warnings);
      continue;
    }
    const offsetMetadata = await readBunOffsetMetadata(
      input,
      payloadResult.candidate.payloadEnd,
      payloadResult.candidate.payloadSize,
      warnings
    );
    findings.push(createBunFinding(sectionStart, sectionSize, payloadResult.candidate, offsetMetadata));
  }
  return { findings, warnings: [...new Set(warnings)] };
};
