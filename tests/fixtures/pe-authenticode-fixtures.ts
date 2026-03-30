"use strict";

import { MockFile } from "../helpers/mock-file.js";
import type {
  PeAuthenticodeBestEffortCore,
  PeAuthenticodeParsedCore
} from "../../analyzers/pe/authenticode-verify.js";
import { inlinePeSectionName } from "../../analyzers/pe/section-name.js";

// Microsoft PE format spec:
// - PE32 Optional Header CheckSum field is at offset 0x40 from the optional header start.
// - Data directory entries are 8 bytes each.
// - The Certificate Table is data directory entry 4 and uses a file offset, not an RVA.
const SYNTHETIC_OPT_OFF = 0;
const SYNTHETIC_DD_START_REL = 100;
const PE_SECURITY_DIRECTORY_INDEX = 4;
const PE_DATA_DIRECTORY_SIZE = 8;
const PE32_CHECKSUM_FIELD_OFFSET = 64;
const PE32_CHECKSUM_FIELD_SIZE = 4;
const BEST_EFFORT_CERT_OFFSET = 160;
const BEST_EFFORT_CERT_SIZE = 20;
const STRICT_HEADERS_END = 160;
const STRICT_SECTION_RAW_OFFSET = 160;
const STRICT_SECTION_RAW_SIZE = 32;
const STRICT_CERT_OFFSET = 192;
const STRICT_CERT_SIZE = 16;
const STRICT_OVERLAY_OFFSET = 224;
const SECURITY_ENTRY_OFFSET =
  SYNTHETIC_OPT_OFF + SYNTHETIC_DD_START_REL + PE_SECURITY_DIRECTORY_INDEX * PE_DATA_DIRECTORY_SIZE;
const AFTER_SECURITY_ENTRY = SECURITY_ENTRY_OFFSET + PE_DATA_DIRECTORY_SIZE;

type ByteRange = { start: number; end: number };

const createNumberedBytes = (byteLength: number): Uint8Array => {
  const bytes = new Uint8Array(byteLength);
  bytes.forEach((_, index) => {
    bytes[index] = index;
  });
  return bytes;
};

const createSecurityDirectory = (rva: number, size: number) => ({
  name: "SECURITY",
  index: PE_SECURITY_DIRECTORY_INDEX,
  rva,
  size
});

export const collectFixtureBytes = (
  bytes: Uint8Array,
  ranges: ByteRange[]
): ArrayBuffer =>
  new Uint8Array(
    ranges.flatMap(range => [...bytes.slice(range.start, range.end)])
  ).buffer;

export const listBestEffortAuthenticodeHashRanges = (byteLength: number): ByteRange[] => [
  { start: 0, end: PE32_CHECKSUM_FIELD_OFFSET },
  { start: PE32_CHECKSUM_FIELD_OFFSET + PE32_CHECKSUM_FIELD_SIZE, end: SECURITY_ENTRY_OFFSET },
  { start: AFTER_SECURITY_ENTRY, end: BEST_EFFORT_CERT_OFFSET },
  { start: BEST_EFFORT_CERT_OFFSET + BEST_EFFORT_CERT_SIZE, end: byteLength }
];

export const listLegacyBestEffortAuthenticodeHashRanges = (byteLength: number): ByteRange[] => [
  { start: 0, end: PE32_CHECKSUM_FIELD_OFFSET },
  { start: PE32_CHECKSUM_FIELD_OFFSET + PE32_CHECKSUM_FIELD_SIZE, end: SECURITY_ENTRY_OFFSET },
  { start: AFTER_SECURITY_ENTRY, end: byteLength }
];

export const listBestEffortAuthenticodeHashRangesWithoutSecurityEntry = (
  byteLength: number
): ByteRange[] => [
  { start: 0, end: PE32_CHECKSUM_FIELD_OFFSET },
  // With no SECURITY directory entry present, Authenticode excludes only the PE checksum field.
  { start: PE32_CHECKSUM_FIELD_OFFSET + PE32_CHECKSUM_FIELD_SIZE, end: byteLength }
];

export const listStrictAuthenticodeHashRanges = (): ByteRange[] => [
  { start: 0, end: PE32_CHECKSUM_FIELD_OFFSET },
  { start: PE32_CHECKSUM_FIELD_OFFSET + PE32_CHECKSUM_FIELD_SIZE, end: SECURITY_ENTRY_OFFSET },
  { start: AFTER_SECURITY_ENTRY, end: STRICT_HEADERS_END },
  { start: STRICT_SECTION_RAW_OFFSET, end: STRICT_CERT_OFFSET }
];

export const listStrictAuthenticodeHashRangesWithoutSecurityEntry = (): ByteRange[] => [
  { start: 0, end: PE32_CHECKSUM_FIELD_OFFSET },
  // With no SECURITY directory entry present, the strict path hashes the full validated header span.
  { start: PE32_CHECKSUM_FIELD_OFFSET + PE32_CHECKSUM_FIELD_SIZE, end: STRICT_HEADERS_END },
  { start: STRICT_SECTION_RAW_OFFSET, end: STRICT_CERT_OFFSET }
];

export const createBestEffortAuthenticodeFixture = (): {
  bytes: Uint8Array;
  checksumFieldOffset: number;
  file: MockFile;
  core: PeAuthenticodeBestEffortCore;
  securityDir: ReturnType<typeof createSecurityDirectory>;
} => {
  // This fixture intentionally models the legacy helper contract only:
  // optOff=0, data directories start at byte 100, and SECURITY is directory entry 4.
  const bytes = createNumberedBytes(200);
  const securityDir = createSecurityDirectory(BEST_EFFORT_CERT_OFFSET, BEST_EFFORT_CERT_SIZE);
  return {
    bytes,
    checksumFieldOffset: PE32_CHECKSUM_FIELD_OFFSET,
    file: new MockFile(bytes, "digest.exe"),
    core: { optOff: SYNTHETIC_OPT_OFF, ddStartRel: SYNTHETIC_DD_START_REL, dataDirs: [securityDir] },
    securityDir
  };
};

export const createStrictAuthenticodeFixture = (): {
  bytes: Uint8Array;
  checksumFieldOffset: number;
  file: MockFile;
  core: PeAuthenticodeParsedCore;
  securityDir: ReturnType<typeof createSecurityDirectory>;
  sectionRawOffset: number;
  sectionRawSize: number;
} => {
  // Microsoft PE format spec, section table:
  // SizeOfRawData is file-aligned and may exceed the section's in-memory VirtualSize.
  // This fixture keeps them equal so the strict Authenticode path hashes headers plus one section only.
  const bytes = createNumberedBytes(256);
  bytes.fill(0xa5, STRICT_OVERLAY_OFFSET);
  const securityDir = createSecurityDirectory(STRICT_CERT_OFFSET, STRICT_CERT_SIZE);
  return {
    bytes,
    checksumFieldOffset: PE32_CHECKSUM_FIELD_OFFSET,
    file: new MockFile(bytes, "overlay-signed.exe"),
    core: {
      optOff: SYNTHETIC_OPT_OFF,
      ddStartRel: SYNTHETIC_DD_START_REL,
      dataDirs: [securityDir],
      opt: { SizeOfHeaders: STRICT_HEADERS_END },
      sections: [
        {
          name: inlinePeSectionName(".text"),
          virtualSize: STRICT_SECTION_RAW_SIZE,
          virtualAddress: 0x1000,
          sizeOfRawData: STRICT_SECTION_RAW_SIZE,
          pointerToRawData: STRICT_SECTION_RAW_OFFSET,
          characteristics: 0x60000020
        }
      ]
    },
    securityDir,
    sectionRawOffset: STRICT_SECTION_RAW_OFFSET,
    sectionRawSize: STRICT_SECTION_RAW_SIZE
  };
};
