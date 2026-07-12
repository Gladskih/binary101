"use strict";

import type {
  BunPayloadStorage,
  BunStandaloneDetectorInput
} from "./types.js";

type BunLengthPrefixBytes = 4 | 8;

export interface BunPayloadCandidate {
  payloadStart: number;
  payloadEnd: number;
  payloadSize: number;
  storage: BunPayloadStorage;
}

type BunPayloadReadResult = { candidate: BunPayloadCandidate | null; warnings: string[] };
type BunPayloadSizeReadResult = { payloadSize: number } | { warning: string };
type BunPayloadBuildResult = { payload: BunPayloadCandidate } | { warning: string };

// Bun StandaloneModuleGraph appends this trailer after the serialized graph offsets.
// https://github.com/oven-sh/bun/blob/main/src/standalone_graph/StandaloneModuleGraph.zig
export const BUN_TRAILER_BYTES = new TextEncoder().encode("\n---- Bun! ----\n");
// Bun 1.3.3 writes a u32 PE payload length, while newer module graphs use u64.
// https://github.com/oven-sh/bun/blob/bun-v1.3.3/src/pe.zig
// https://github.com/oven-sh/bun/blob/main/src/standalone_graph/StandaloneModuleGraph.zig
const BUN_LENGTH_PREFIX_U32_BYTES: BunLengthPrefixBytes = 4;
const BUN_LENGTH_PREFIX_U64_BYTES: BunLengthPrefixBytes = 8;

const hasBytes = (readerSize: number, offset: number, size: number): boolean =>
  Number.isSafeInteger(offset) &&
  Number.isSafeInteger(size) &&
  offset >= 0 &&
  size >= 0 &&
  offset <= readerSize &&
  size <= readerSize - offset;

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
};

const rejectPayload = (warning: string): BunPayloadReadResult => ({
  candidate: null,
  warnings: [warning]
});

const readPayloadLength = (view: DataView, prefixBytes: BunLengthPrefixBytes): bigint | null => {
  if (view.byteLength < prefixBytes) return null;
  return prefixBytes === BUN_LENGTH_PREFIX_U32_BYTES
    ? BigInt(view.getUint32(0, true))
    : view.getBigUint64(0, true);
};

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
  sectionSize: number,
  prefixBytes: BunLengthPrefixBytes
): Promise<BunPayloadSizeReadResult> => {
  if (sectionSize < prefixBytes) {
    return { warning: `Bun .bun section is truncated before its ${prefixBytes}-byte payload length.` };
  }
  if (!hasBytes(input.reader.size, sectionStart, prefixBytes)) {
    return { warning: "Bun .bun section raw data starts outside the file." };
  }
  const lengthView = await input.reader.read(sectionStart, prefixBytes);
  const payloadSize = readPayloadLength(lengthView, prefixBytes);
  if (payloadSize == null) {
    return { warning: `Bun .bun section is truncated before its ${prefixBytes}-byte payload length.` };
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
  payloadSize: number,
  prefixBytes: BunLengthPrefixBytes,
  storage: BunPayloadStorage
): BunPayloadBuildResult => {
  const payloadStart = sectionStart + prefixBytes;
  const payloadEnd = payloadStart + payloadSize;
  if (!Number.isSafeInteger(payloadEnd)) {
    return { warning: "Bun .bun declared payload range exceeds Number.MAX_SAFE_INTEGER." };
  }
  if (payloadSize < BUN_TRAILER_BYTES.byteLength) {
    return { warning: "Bun .bun payload is too small to contain the Bun trailer." };
  }
  if (payloadSize > sectionSize - prefixBytes ||
      !hasBytes(input.reader.size, payloadStart, payloadSize)) {
    return { warning: "Bun .bun declared payload length extends past the section or EOF." };
  }
  return { payload: { payloadStart, payloadEnd, payloadSize, storage } };
};

const readLengthPrefixedPayload = async (
  input: BunStandaloneDetectorInput,
  sectionStart: number,
  sectionSize: number,
  prefixBytes: BunLengthPrefixBytes,
  storage: BunPayloadStorage
): Promise<BunPayloadReadResult> => {
  const sizeResult = await readLengthPrefixedPayloadSize(input, sectionStart, sectionSize, prefixBytes);
  if ("warning" in sizeResult) return rejectPayload(sizeResult.warning);
  const buildResult = buildLengthPrefixedPayload(
    input,
    sectionStart,
    sectionSize,
    sizeResult.payloadSize,
    prefixBytes,
    storage
  );
  if ("warning" in buildResult) return rejectPayload(buildResult.warning);
  return await readTrailerMatches(input, buildResult.payload.payloadEnd)
    ? { candidate: buildResult.payload, warnings: [] }
    : rejectPayload("Bun .bun payload is missing the expected standalone module-graph trailer.");
};

const readDirectPayload = async (
  input: BunStandaloneDetectorInput,
  sectionStart: number,
  sectionSize: number,
  virtualSize: number
): Promise<BunPayloadCandidate | null> => {
  const payloadSize = virtualSize > 0 && virtualSize <= sectionSize ? virtualSize : sectionSize;
  if (payloadSize < BUN_TRAILER_BYTES.byteLength ||
      !hasBytes(input.reader.size, sectionStart, payloadSize)) return null;
  const payloadEnd = sectionStart + payloadSize;
  return await readTrailerMatches(input, payloadEnd)
    ? { payloadStart: sectionStart, payloadEnd, payloadSize, storage: "section-virtual-data" }
    : null;
};

export const readBunPayload = async (
  input: BunStandaloneDetectorInput,
  sectionStart: number,
  sectionSize: number,
  virtualSize: number
): Promise<BunPayloadReadResult> => {
  const u32Prefixed = await readLengthPrefixedPayload(
    input,
    sectionStart,
    sectionSize,
    BUN_LENGTH_PREFIX_U32_BYTES,
    "u32-length-prefixed"
  );
  if (u32Prefixed.candidate) return u32Prefixed;
  const u64Prefixed = await readLengthPrefixedPayload(
    input,
    sectionStart,
    sectionSize,
    BUN_LENGTH_PREFIX_U64_BYTES,
    "u64-length-prefixed"
  );
  if (u64Prefixed.candidate) return u64Prefixed;
  const direct = await readDirectPayload(input, sectionStart, sectionSize, virtualSize);
  return direct ? { candidate: direct, warnings: [] } : {
    candidate: null,
    warnings: [...new Set([...u32Prefixed.warnings, ...u64Prefixed.warnings])]
  };
};
