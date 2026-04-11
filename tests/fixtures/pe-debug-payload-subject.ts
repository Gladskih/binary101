"use strict";

import { MockFile } from "../helpers/mock-file.js";

const encoder = new TextEncoder();
// Microsoft PE/COFF, IMAGE_DEBUG_DIRECTORY entry size is 28 bytes.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
const IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE = 28;
// LLVM and other PE parsers use these IMAGE_DEBUG_DIRECTORY.Type values:
// VC_FEATURE = 12, POGO = 13.
// https://llvm.org/doxygen/BinaryFormat_2COFF_8h_source.html
const IMAGE_DEBUG_TYPE_VC_FEATURE = 12;
const IMAGE_DEBUG_TYPE_POGO = 13;

// Upstream PE parsers model VC_FEATURE as five DWORD counters:
// https://raw.githubusercontent.com/saferwall/pe/main/debug.go
const VC_FEATURE_COUNTER_COUNT = 5;
const DWORD_SIZE = 4;

// Upstream PE parsers recognize 0x4C544347 as the LTCG POGO signature:
// https://raw.githubusercontent.com/saferwall/pe/main/debug.go
export const POGO_SIGNATURE_LTCG = 0x4c544347;
export const POGO_SIGNATURE_NAME_LTCG = "LTCG";

type PogoSubjectEntry = { startRva: number; size: number; name: string };
type VcFeatureSubjectCounters = [number, number, number, number, number];

const createSyntheticSubjectToken = (seed = 0): string => `s${seed.toString(36)}`;

export const createSyntheticBinaryName = (seed = 0): string =>
  `${createSyntheticSubjectToken(seed)}.bin`;

export const createSyntheticPdbPath = (seed = 0): string =>
  `${createSyntheticSubjectToken(seed)}.pdb`;

export const createSyntheticLongPdbPath = (payloadLength: number, seed = 0): string =>
  `${createSyntheticSubjectToken(seed)}-${"x".repeat(payloadLength)}.pdb`;

export const createSyntheticPogoEntryName = (seed = 0): string =>
  `n${createSyntheticSubjectToken(seed)}`;

export const createSyntheticWarning = (seed = 0): string =>
  `w-${createSyntheticSubjectToken(seed)}`;

export const createPayloadFile = (
  payload: Uint8Array,
  name = createSyntheticBinaryName(payload.length)
): MockFile => new MockFile(payload, name);

const createSyntheticOffsetPayloadPadding = (payloadLength: number): number => payloadLength + 1;

export const createOffsetPayloadSubject = (
  payload: Uint8Array,
  name = createSyntheticBinaryName(
    payload.length + createSyntheticOffsetPayloadPadding(payload.length)
  )
): { file: MockFile; offset: number } => {
  const offset = createSyntheticOffsetPayloadPadding(payload.length);
  const bytes = new Uint8Array(offset + payload.length);
  bytes.set(payload, offset);
  return { file: new MockFile(bytes, name), offset };
};

export const createVcFeatureSubjectCounters = (seed = 0): VcFeatureSubjectCounters => [
  seed + 1,
  seed + 2,
  seed + 3,
  seed + 4,
  seed + 5
];

export const createVcFeatureSubjectInfo = (
  counters = createVcFeatureSubjectCounters()
) => ({
  preVc11: counters[0],
  cAndCpp: counters[1],
  gs: counters[2],
  sdl: counters[3],
  guardN: counters[4]
});

export const createVcFeaturePayload = (
  counters: VcFeatureSubjectCounters
): Uint8Array => {
  const bytes = new Uint8Array(VC_FEATURE_COUNTER_COUNT * DWORD_SIZE);
  const view = new DataView(bytes.buffer);
  counters.forEach((value, index) => {
    view.setUint32(index * DWORD_SIZE, value, true);
  });
  return bytes;
};

export const createTruncatedVcFeaturePayload = (): Uint8Array =>
  new Uint8Array(VC_FEATURE_COUNTER_COUNT * DWORD_SIZE - 1);

const align4 = (value: number): number => (value + 3) & ~3;

export const createPogoPayload = (
  signature: number,
  entries: PogoSubjectEntry[]
): Uint8Array => {
  const blocks = entries.map(({ name, size, startRva }) => {
    const nameBytes = encoder.encode(`${name}\0`);
    const block = new Uint8Array(align4(8 + nameBytes.length));
    const view = new DataView(block.buffer);
    view.setUint32(0, startRva, true);
    view.setUint32(4, size, true);
    block.set(nameBytes, 8);
    return block;
  });
  const bytes = new Uint8Array(4 + blocks.reduce((sum, block) => sum + block.length, 0));
  const view = new DataView(bytes.buffer);
  view.setUint32(0, signature, true);
  let offset = 4;
  blocks.forEach(block => {
    bytes.set(block, offset);
    offset += block.length;
  });
  return bytes;
};

export const createPogoSubjectEntries = (count: number): PogoSubjectEntry[] =>
  Array.from({ length: count }, (_, index) => ({
    startRva: index + 1,
    size: index + 2,
    name: createSyntheticPogoEntryName(index)
  }));

export const createPogoSubjectInfo = (count = 2) => ({
  signature: POGO_SIGNATURE_LTCG,
  signatureName: POGO_SIGNATURE_NAME_LTCG,
  entries: createPogoSubjectEntries(count)
});

export const createTruncatedPogoPayload = (): Uint8Array =>
  createPogoPayload(POGO_SIGNATURE_LTCG, createPogoSubjectEntries(1)).slice(0, -1);

export const createDebugDirectorySubject = (
  entries: Array<{ payload: Uint8Array; type: number }>
): {
  dataDirs: Array<{ name: string; rva: number; size: number }>;
  file: MockFile;
} => {
  const directoryRva = IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE * (entries.length + 1);
  const payloadStart = directoryRva + entries.length * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE;
  let cursor = payloadStart;
  const byteLength = entries.reduce(
    (total, entry) => Math.max(total, cursor += entry.payload.length),
    payloadStart + entries.length * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE
  );
  const bytes = new Uint8Array(byteLength).fill(0);
  const view = new DataView(bytes.buffer);
  cursor = payloadStart;
  entries.forEach((entry, index) => {
    const dirOffset = directoryRva + index * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE;
    view.setUint32(dirOffset + 12, entry.type, true);
    view.setUint32(dirOffset + 16, entry.payload.length, true);
    view.setUint32(dirOffset + 20, cursor, true);
    view.setUint32(dirOffset + 24, cursor, true);
    bytes.set(entry.payload, cursor);
    cursor += entry.payload.length;
  });
  return {
    dataDirs: [{
      name: "DEBUG",
      rva: directoryRva,
      size: entries.length * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE
    }],
    file: new MockFile(bytes, createSyntheticBinaryName(entries.length))
  };
};

export const createVcFeatureDebugDirectorySubject = () => {
  const counters = createVcFeatureSubjectCounters();
  return {
    ...createDebugDirectorySubject([{
      payload: createVcFeaturePayload(counters),
      type: IMAGE_DEBUG_TYPE_VC_FEATURE
    }]),
    expected: createVcFeatureSubjectInfo(counters)
  };
};

export const createPogoDebugDirectorySubject = (count = 2) => {
  const expected = createPogoSubjectInfo(count);
  return {
    ...createDebugDirectorySubject([{
      payload: createPogoPayload(expected.signature, expected.entries),
      type: IMAGE_DEBUG_TYPE_POGO
    }]),
    expected
  };
};
