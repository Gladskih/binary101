"use strict";

import type {
  NsisInstallerDetectorInput,
  PeNsisPackerFinding,
  PePackerDetectorResult
} from "./types.js";

// NSIS firstheader contains seven 32-bit integer fields.
// https://github.com/kichik/nsis/blob/master/Source/exehead/fileform.h
const FIRSTHEADER_BYTES = Int32Array.BYTES_PER_ELEMENT * 7;
const NSIS_FLAGS_OFFSET = 0;
const NSIS_SIGINFO_OFFSET = Int32Array.BYTES_PER_ELEMENT;
const NSIS_NSINST_OFFSET = Int32Array.BYTES_PER_ELEMENT * 2;
const NSIS_LENGTH_OF_HEADER_OFFSET = Int32Array.BYTES_PER_ELEMENT * 5;
const NSIS_LENGTH_OF_ALL_FOLLOWING_DATA_OFFSET = Int32Array.BYTES_PER_ELEMENT * 6;
const FH_FLAGS_UNINSTALL = 1;
const FH_FLAGS_SILENT = 2;
const FH_FLAGS_NO_CRC = 4;
const FH_FLAGS_FORCE_CRC = 8;
const FH_FLAGS_MASK = FH_FLAGS_UNINSTALL | FH_FLAGS_SILENT | FH_FLAGS_NO_CRC | FH_FLAGS_FORCE_CRC;
// NSIS firstheader.siginfo is FH_SIG.
// https://github.com/kichik/nsis/blob/master/Source/exehead/fileform.h
const FH_SIG = 0xdeadbeef;
// NSIS firstheader stores these little-endian integers as "NullsoftInst".
// https://github.com/kichik/nsis/blob/master/Source/exehead/fileform.h
const FH_INT1 = 0x6c6c754e;
const FH_INT2 = 0x74666f73;
const FH_INT3 = 0x74736e49;

const hasNsisSignature = (view: DataView): boolean =>
  view.byteLength >= NSIS_LENGTH_OF_HEADER_OFFSET &&
  view.getUint32(NSIS_SIGINFO_OFFSET, true) === FH_SIG &&
  view.getUint32(NSIS_NSINST_OFFSET, true) === FH_INT1 &&
  view.getUint32(NSIS_NSINST_OFFSET + Int32Array.BYTES_PER_ELEMENT, true) === FH_INT2 &&
  view.getUint32(NSIS_NSINST_OFFSET + Int32Array.BYTES_PER_ELEMENT * 2, true) === FH_INT3;

const hasPartialNsisSignal = (view: DataView): boolean =>
  (view.byteLength >= NSIS_NSINST_OFFSET && view.getUint32(NSIS_SIGINFO_OFFSET, true) === FH_SIG) ||
  (
    view.byteLength >= NSIS_NSINST_OFFSET + Int32Array.BYTES_PER_ELEMENT &&
    view.getUint32(NSIS_NSINST_OFFSET, true) === FH_INT1
  );

const createNsisFinding = (
  start: number,
  flags: number,
  lengthOfHeader: number,
  lengthOfAllFollowingData: number
): PeNsisPackerFinding => ({
  id: "nsis-installer",
  name: "NSIS installer",
  kind: "installer",
  confidence: "high",
  evidence: [
    "True overlay starts with the NSIS firstheader structure.",
    "firstheader contains the NullsoftInst signature and bounded lengths."
  ],
  compressedHeaderSize: lengthOfHeader,
  firstHeaderOffset: start,
  flags,
  followingDataSize: lengthOfAllFollowingData
});

const validateNsisFirstHeader = (
  view: DataView,
  start: number,
  end: number,
  warnings: string[]
): PeNsisPackerFinding | null => {
  if (view.byteLength < FIRSTHEADER_BYTES) {
    if (hasPartialNsisSignal(view)) warnings.push("NSIS firstheader is truncated by EOF.");
    return null;
  }
  if (!hasNsisSignature(view)) return null;
  const flags = view.getInt32(NSIS_FLAGS_OFFSET, true);
  const lengthOfHeader = view.getInt32(NSIS_LENGTH_OF_HEADER_OFFSET, true);
  const lengthOfAllFollowingData = view.getInt32(NSIS_LENGTH_OF_ALL_FOLLOWING_DATA_OFFSET, true);
  if ((flags & ~FH_FLAGS_MASK) !== 0) {
    warnings.push("NSIS firstheader has unsupported flag bits set.");
    return null;
  }
  if (lengthOfHeader <= 0) {
    warnings.push("NSIS firstheader length_of_header is not positive.");
    return null;
  }
  if (lengthOfAllFollowingData < FIRSTHEADER_BYTES) {
    warnings.push("NSIS firstheader length_of_all_following_data is smaller than firstheader.");
    return null;
  }
  if (lengthOfHeader > lengthOfAllFollowingData - FIRSTHEADER_BYTES) {
    warnings.push("NSIS firstheader length_of_header exceeds the following data span.");
    return null;
  }
  const dataEnd = start + lengthOfAllFollowingData;
  if (!Number.isSafeInteger(dataEnd) || dataEnd > end) {
    warnings.push("NSIS firstheader length_of_all_following_data extends past the true overlay range.");
    return null;
  }
  return createNsisFinding(start, flags, lengthOfHeader, lengthOfAllFollowingData);
};

export const detectNsisInstaller = async (
  input: NsisInstallerDetectorInput
): Promise<PePackerDetectorResult<PeNsisPackerFinding>> => {
  const findings: PeNsisPackerFinding[] = [];
  const warnings: string[] = [];
  for (const range of input.overlay?.ranges ?? []) {
    const view = await input.reader.read(range.start, FIRSTHEADER_BYTES);
    const finding = validateNsisFirstHeader(view, range.start, range.end, warnings);
    if (finding) findings.push(finding);
  }
  return { findings, warnings };
};
