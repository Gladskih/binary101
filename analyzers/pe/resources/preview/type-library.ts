"use strict";

import { isAsciiPlaceholderPayload } from "./mui-placeholder.js";
import type {
  ResourcePreviewField,
  ResourcePreviewResult,
  ResourceTypeLibraryPreview,
  ResourceTypeLibrarySegmentPreview
} from "./types.js";
import type { MuiResourceConfiguration } from "../mui-config.js";

// ReactOS/Wine typelib_struct.h documents the known typelib signatures as four-byte
// ASCII values, "MSFT" and "SLTG".
// https://doxygen.reactos.org/d1/daf/typelib__struct_8h_source.html
const TYPELIB_SIGNATURE_SIZE = 4;
// ReactOS/Wine typelib_struct.h defines a 0x54-byte MSFT_Header followed by
// 15 MSFT_pSeg records of 0x10 bytes each in MSFT_SegDir.
// https://doxygen.reactos.org/d1/daf/typelib__struct_8h_source.html
const MSFT_HEADER_SIZE = 0x54;
const MSFT_SEGMENT_SIZE = 0x10;
const MSFT_SEGMENT_DIRECTORY_OFFSET = MSFT_HEADER_SIZE;
const MSFT_SEGMENT_NAMES = [
  "TypeInfoTab",
  "ImpInfo",
  "ImpFiles",
  "RefTab",
  "GuidHashTab",
  "GuidTab",
  "NameHashTab",
  "NameTab",
  "StringTab",
  "TypdescTab",
  "ArrayDescriptions",
  "CustData",
  "CDGuids",
  "Reserved0E",
  "Reserved0F"
];
// Field offsets match ReactOS/Wine tagMSFT_Header byte offsets.
// Source: https://doxygen.reactos.org/d1/daf/typelib__struct_8h_source.html
const MSFT_HEADER_FIELD_OFFSETS = {
  version: 4,
  libraryGuidOffset: 8,
  localeId: 12,
  localeId2: 16,
  varFlags: 20,
  libraryVersion: 24,
  flags: 28,
  typeInfoCount: 32,
  nameTableEntries: 48,
  nameTableChars: 52,
  nameOffset: 56,
  importInfoCount: 80
} as const;

const readAsciiSignature = (data: Uint8Array): string =>
  new TextDecoder("us-ascii").decode(data.subarray(0, TYPELIB_SIGNATURE_SIZE));

const formatHex32 = (value: number): string => {
  // A 32-bit value contains 8 hexadecimal digits because each digit encodes 4 bits.
  return `0x${(value >>> 0).toString(16).padStart(8, "0")}`;
};

const formatSignedOffset = (value: number): string =>
  value < 0 ? String(value) : formatHex32(value);

const buildTypeLibraryPreview = (
  typeLibrary: ResourceTypeLibraryPreview,
  issues: string[] = []
): ResourcePreviewResult => ({
  preview: {
    previewKind: "typeLibrary",
    typeLibrary,
    previewFields: [
      { label: "Type", value: "TYPELIB" },
      { label: "Format", value: typeLibrary.format }
    ]
  },
  ...(issues.length ? { issues } : {})
});

const readMsftHeaderFields = (view: DataView): ResourcePreviewField[] => [
  {
    label: "Format version",
    value: formatHex32(view.getUint32(MSFT_HEADER_FIELD_OFFSETS.version, true))
  },
  {
    label: "Library GUID offset",
    value: formatSignedOffset(view.getInt32(MSFT_HEADER_FIELD_OFFSETS.libraryGuidOffset, true))
  },
  {
    label: "LCID",
    value: formatHex32(view.getUint32(MSFT_HEADER_FIELD_OFFSETS.localeId, true))
  },
  {
    label: "LCID 2",
    value: formatHex32(view.getUint32(MSFT_HEADER_FIELD_OFFSETS.localeId2, true))
  },
  {
    label: "Var flags",
    value: formatHex32(view.getUint32(MSFT_HEADER_FIELD_OFFSETS.varFlags, true))
  },
  {
    label: "Library version",
    value: formatHex32(view.getUint32(MSFT_HEADER_FIELD_OFFSETS.libraryVersion, true))
  },
  {
    label: "Flags",
    value: formatHex32(view.getUint32(MSFT_HEADER_FIELD_OFFSETS.flags, true))
  },
  {
    label: "Type infos",
    value: String(view.getUint32(MSFT_HEADER_FIELD_OFFSETS.typeInfoCount, true))
  },
  {
    label: "Name table entries",
    value: String(view.getUint32(MSFT_HEADER_FIELD_OFFSETS.nameTableEntries, true))
  },
  {
    label: "Name table chars",
    value: String(view.getUint32(MSFT_HEADER_FIELD_OFFSETS.nameTableChars, true))
  },
  {
    label: "Name offset",
    value: formatSignedOffset(view.getInt32(MSFT_HEADER_FIELD_OFFSETS.nameOffset, true))
  },
  {
    label: "Import infos",
    value: String(view.getUint32(MSFT_HEADER_FIELD_OFFSETS.importInfoCount, true))
  }
];

const validateMsftSegment = (
  segment: ResourceTypeLibrarySegmentPreview,
  dataLength: number,
  issues: string[]
): void => {
  // ReactOS/Wine initialize unused MSFT_pSeg slots with offset -1 and length 0.
  // https://doxygen.reactos.org/d4/df2/write__msft_8c_source.html
  if (segment.offset === -1 && segment.length === 0) return;
  if (segment.offset < 0 || segment.length < 0) {
    issues.push(`TYPELIB MSFT segment ${segment.name} has a negative offset or length.`);
    return;
  }
  if (segment.offset > dataLength || segment.length > dataLength - segment.offset) {
    issues.push(`TYPELIB MSFT segment ${segment.name} points outside the resource data.`);
  }
};

const readMsftSegments = (
  view: DataView,
  dataLength: number,
  issues: string[]
): ResourceTypeLibrarySegmentPreview[] => {
  if (
    dataLength <
    MSFT_SEGMENT_DIRECTORY_OFFSET + MSFT_SEGMENT_NAMES.length * MSFT_SEGMENT_SIZE
  ) {
    issues.push("TYPELIB MSFT segment directory is truncated.");
    return [];
  }
  return MSFT_SEGMENT_NAMES.map((name, index) => {
    const offset = MSFT_SEGMENT_DIRECTORY_OFFSET + index * MSFT_SEGMENT_SIZE;
    // MSFT_pSeg starts with offset, then length; both are 32-bit signed fields.
    // Source: https://doxygen.reactos.org/d1/daf/typelib__struct_8h_source.html
    const segment = {
      name,
      offset: view.getInt32(offset, true),
      length: view.getInt32(offset + 4, true)
    };
    validateMsftSegment(segment, dataLength, issues);
    return segment;
  });
};

const parseMsftTypeLibrary = (data: Uint8Array): ResourcePreviewResult => {
  const issues: string[] = [];
  if (data.length < MSFT_HEADER_SIZE) {
    return { issues: ["TYPELIB MSFT header is truncated."] };
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return buildTypeLibraryPreview(
    {
      format: "MSFT",
      headerFields: readMsftHeaderFields(view),
      segments: readMsftSegments(view, data.length, issues)
    },
    [...new Set(issues)]
  );
};

const parseSltgTypeLibrary = (data: Uint8Array): ResourcePreviewResult =>
  buildTypeLibraryPreview({
    format: "SLTG",
    headerFields: [
      { label: "Signature", value: readAsciiSignature(data) },
      { label: "Size", value: `${data.length} bytes` }
    ],
    segments: []
  });

export function addTypeLibraryPreview(
  data: Uint8Array,
  typeName: string,
  muiResourceConfiguration: MuiResourceConfiguration | null
): ResourcePreviewResult | null {
  if (typeName !== "TYPELIB") return null;
  if (muiResourceConfiguration && isAsciiPlaceholderPayload(data)) {
    return buildTypeLibraryPreview({
      format: "placeholder",
      headerFields: [{ label: "Note", value: "MUI placeholder payload" }],
      segments: []
    });
  }
  if (data.length < TYPELIB_SIGNATURE_SIZE) {
    return { issues: ["TYPELIB resource is too small to read a signature."] };
  }
  const signature = readAsciiSignature(data);
  // ReactOS/Wine typelib_struct.h documents the two known typelib signatures:
  // ICreateTypeLib writes "SLTG", while ICreateTypeLib2 writes "MSFT".
  // https://doxygen.reactos.org/d1/daf/typelib__struct_8h_source.html
  if (signature === "MSFT") return parseMsftTypeLibrary(data);
  if (signature === "SLTG") return parseSltgTypeLibrary(data);
  return buildTypeLibraryPreview({
    format: "unknown",
    headerFields: [
      { label: "Signature", value: signature },
      { label: "Size", value: `${data.length} bytes` }
    ],
    segments: []
  });
}
