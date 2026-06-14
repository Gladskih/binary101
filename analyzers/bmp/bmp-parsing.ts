"use strict";
import type { BmpBitmaskChannel, BmpBitmasks, BmpCieXyz, BmpCieXyzTriple, BmpDibHeader } from "./types.js";
export const FILE_HEADER_SIZE = 14;
export const MAX_PREFIX_BYTES = 1024 * 1024;
const COLOR_SPACE_TYPE_NAMES: Record<number, string> = {
  0x00000000: "LCS_CALIBRATED_RGB",
  0x73524742: "LCS_sRGB",
  0x57696e20: "LCS_WINDOWS_COLOR_SPACE",
  0x4c494e4b: "PROFILE_LINKED",
  0x4d424544: "PROFILE_EMBEDDED"
};
const INTENT_NAMES: Record<number, string> = {
  1: "LCS_GM_BUSINESS",
  2: "LCS_GM_GRAPHICS",
  4: "LCS_GM_IMAGES",
  8: "LCS_GM_ABS_COLORIMETRIC"
};
const COMPRESSION_NAMES: Record<number, string> = {
  0: "BI_RGB (uncompressed)",
  1: "BI_RLE8 (RLE 8-bit)",
  2: "BI_RLE4 (RLE 4-bit)",
  3: "BI_BITFIELDS (uncompressed with masks)",
  4: "BI_JPEG",
  5: "BI_PNG",
  6: "BI_ALPHABITFIELDS (uncompressed with alpha mask)",
  11: "BI_CMYK",
  12: "BI_CMYKRLE8",
  13: "BI_CMYKRLE4"
};
export const readUint16le = (bytes: Uint8Array, offset: number): number | null => {
  if (offset + 2 > bytes.length) return null;
  return (bytes[offset] ?? 0) | ((bytes[offset + 1] ?? 0) << 8);
};
export const readUint32le = (bytes: Uint8Array, offset: number): number | null => {
  if (offset + 4 > bytes.length) return null;
  return (
    (bytes[offset] ?? 0) |
    ((bytes[offset + 1] ?? 0) << 8) |
    ((bytes[offset + 2] ?? 0) << 16) |
    ((bytes[offset + 3] ?? 0) << 24)
  ) >>> 0;
};
export const readInt32le = (bytes: Uint8Array, offset: number): number | null => {
  const value = readUint32le(bytes, offset);
  if (value == null) return null;
  return value > 0x7fffffff ? value - 0x1_0000_0000 : value;
};
export const describeCompression = (compression: number | null): string | null => {
  if (compression == null) return null;
  return COMPRESSION_NAMES[compression] || `Unknown (${compression})`;
};
export const describeColorSpaceType = (value: number | null): string | null => {
  if (value == null) return null;
  return COLOR_SPACE_TYPE_NAMES[value] || `Unknown (${value})`;
};
export const describeIntent = (value: number | null): string | null => {
  if (value == null) return null;
  return INTENT_NAMES[value] || `Unknown (${value})`;
};
export const describeDibKind = (dibSize: number | null): string | null => {
  if (dibSize == null) return null;
  if (dibSize === 12) return "BITMAPCOREHEADER";
  if (dibSize === 40) return "BITMAPINFOHEADER";
  if (dibSize === 52) return "BITMAPV2INFOHEADER";
  if (dibSize === 56) return "BITMAPV3INFOHEADER";
  if (dibSize === 64) return "BITMAPINFOHEADER2";
  if (dibSize === 108) return "BITMAPV4HEADER";
  if (dibSize === 124) return "BITMAPV5HEADER";
  if (dibSize >= 40) return `DIB (${dibSize} bytes)`;
  return `Core DIB (${dibSize} bytes)`;
};
export const buildBitmaskChannel = (mask: number | null): BmpBitmaskChannel | null => {
  const normalized = mask == null ? 0 : mask >>> 0;
  if (!normalized) return null;
  let shift = 0;
  let shifted = normalized;
  while ((shifted & 1) === 0 && shift < 32) {
    shifted >>>= 1;
    shift += 1;
  }
  let bits = 0;
  while ((shifted & 1) === 1 && bits < 32) {
    shifted >>>= 1;
    bits += 1;
  }
  const contiguous = shifted === 0;
  return { mask: normalized, shift, bits, contiguous };
};
export const computeRowStride = (width: number | null, bitsPerPixel: number | null): number | null => {
  if (width == null || bitsPerPixel == null) return null;
  if (!Number.isFinite(width) || width <= 0) return null;
  if (!Number.isFinite(bitsPerPixel) || bitsPerPixel <= 0) return null;
  const bitsPerRow = bitsPerPixel * width;
  return Math.floor((bitsPerRow + 31) / 32) * 4;
};
export const isUncompressedLayout = (compression: number | null): boolean =>
  compression == null || compression === 0 || compression === 3 || compression === 6;
export type ParsedDibHeader = {
  dibSize: number | null;
  dibHeader: BmpDibHeader;
  masksAfterHeaderBytes: number;
};
type DibHeaderDraft = Omit<BmpDibHeader,
  "headerKind" | "compressionName" | "colorSpaceTypeName" | "intentName" | "profile" | "truncated"
>;
const buildCieXyz = (bytes: Uint8Array, offset: number): BmpCieXyz => ({
  x: readInt32le(bytes, offset),
  y: readInt32le(bytes, offset + 4),
  z: readInt32le(bytes, offset + 8)
});
const buildCieXyzTriple = (bytes: Uint8Array, offset: number): BmpCieXyzTriple => ({
  red: buildCieXyz(bytes, offset),
  green: buildCieXyz(bytes, offset + 12),
  blue: buildCieXyz(bytes, offset + 24)
});
const warnMaskContiguity = (masks: BmpBitmasks, pushIssue: (message: string) => void): void => {
  const channels: Array<[string, BmpBitmaskChannel | null]> = [
    ["Red", masks.red],
    ["Green", masks.green],
    ["Blue", masks.blue],
    ["Alpha", masks.alpha]
  ];
  for (const [name, channel] of channels) {
    if (channel && !channel.contiguous) {
      pushIssue(`${name} mask is not a contiguous run of bits (mask=${channel.mask.toString(16)}).`);
    }
  }
};
const createDibHeaderDraft = (dibSize: number | null): DibHeaderDraft => ({
  headerSize: dibSize,
  width: null,
  height: null,
  signedHeight: null,
  topDown: null,
  planes: null,
  bitsPerPixel: null,
  compression: null,
  imageSize: null,
  xPixelsPerMeter: null,
  yPixelsPerMeter: null,
  colorsUsed: null,
  importantColors: null,
  masks: null,
  colorSpaceType: null,
  endpoints: null,
  gammaRed: null,
  gammaGreen: null,
  gammaBlue: null,
  intent: null,
  profileDataOffset: null,
  profileSize: null,
  reserved: null
});
const readCoreDibHeader = (bytes: Uint8Array, draft: DibHeaderDraft): void => {
  draft.width = readUint16le(bytes, 18);
  draft.height = readUint16le(bytes, 20);
  draft.signedHeight = draft.height;
  draft.topDown = false;
  draft.planes = readUint16le(bytes, 22);
  draft.bitsPerPixel = readUint16le(bytes, 24);
};
const buildBitmasks = (
  bytes: Uint8Array,
  includeAlpha: boolean,
  alphaOffset: number
): BmpBitmasks => ({
  red: buildBitmaskChannel(readUint32le(bytes, 54)),
  green: buildBitmaskChannel(readUint32le(bytes, 58)),
  blue: buildBitmaskChannel(readUint32le(bytes, 62)),
  alpha: buildBitmaskChannel(includeAlpha ? readUint32le(bytes, alphaOffset) : null)
});
const readInfoDibBase = (bytes: Uint8Array, draft: DibHeaderDraft): void => {
  draft.width = readInt32le(bytes, 18);
  draft.signedHeight = readInt32le(bytes, 22);
  if (draft.signedHeight != null) {
    draft.topDown = draft.signedHeight < 0;
    draft.height = Math.abs(draft.signedHeight);
  }
  draft.planes = readUint16le(bytes, 26);
  draft.bitsPerPixel = readUint16le(bytes, 28);
  draft.compression = readUint32le(bytes, 30);
  draft.imageSize = readUint32le(bytes, 34);
  draft.xPixelsPerMeter = readInt32le(bytes, 38);
  draft.yPixelsPerMeter = readInt32le(bytes, 42);
  draft.colorsUsed = readUint32le(bytes, 46);
  draft.importantColors = readUint32le(bytes, 50);
};
const readHeaderContainedMasks = (
  bytes: Uint8Array,
  dibSize: number,
  draft: DibHeaderDraft
): void => {
  if (dibSize === 52 || dibSize === 56 || dibSize >= 108) {
    draft.masks = buildBitmasks(bytes, dibSize >= 56, 66);
  }
};
const readColorSpaceFields = (bytes: Uint8Array, dibSize: number, draft: DibHeaderDraft): void => {
  if (dibSize < 108) return;
  draft.colorSpaceType = readUint32le(bytes, 70);
  draft.endpoints = buildCieXyzTriple(bytes, 74);
  draft.gammaRed = readUint32le(bytes, 110);
  draft.gammaGreen = readUint32le(bytes, 114);
  draft.gammaBlue = readUint32le(bytes, 118);
};
const readProfileFields = (bytes: Uint8Array, dibSize: number, draft: DibHeaderDraft): void => {
  if (dibSize < 124) return;
  draft.intent = readUint32le(bytes, 122);
  draft.profileDataOffset = readUint32le(bytes, 126);
  draft.profileSize = readUint32le(bytes, 130);
  draft.reserved = readUint32le(bytes, 134);
};
const readExtraBitfieldMasks = async (
  headerBytes: Uint8Array,
  dibSize: number,
  draft: DibHeaderDraft,
  fileSize: number,
  ensureBytes: (required: number) => Promise<Uint8Array>,
  pushIssue: (message: string) => void
): Promise<{ headerBytes: Uint8Array; masksAfterHeaderBytes: number }> => {
  if (dibSize !== 40 || (draft.compression !== 3 && draft.compression !== 6)) {
    return { headerBytes, masksAfterHeaderBytes: 0 };
  }
  const masksAfterHeaderBytes = draft.compression === 6 ? 16 : 12;
  const required = FILE_HEADER_SIZE + dibSize + masksAfterHeaderBytes;
  const extendedHeaderBytes = await ensureBytes(required);
  draft.masks = buildBitmasks(extendedHeaderBytes, draft.compression === 6, 66);
  if (required > fileSize) pushIssue("BITFIELDS masks truncated (file ends early).");
  return { headerBytes: extendedHeaderBytes, masksAfterHeaderBytes };
};
const validateDibHeaderDraft = (
  draft: DibHeaderDraft,
  pushIssue: (message: string) => void
): void => {
  if (draft.width != null && draft.width <= 0) pushIssue(`Width is non-positive (${draft.width}).`);
  if (draft.height != null && draft.height <= 0) pushIssue(`Height is non-positive (${draft.height}).`);
  if (draft.planes != null && draft.planes !== 1) pushIssue(`Planes value is unusual (${draft.planes}); expected 1.`);
  if (draft.topDown && draft.compression != null && draft.compression !== 0 && draft.compression !== 3) {
    pushIssue("Top-down BMPs should use BI_RGB or BI_BITFIELDS (compression is restricted for negative heights).");
  }
  if (draft.masks) warnMaskContiguity(draft.masks, pushIssue);
};
const completeDibHeader = (
  draft: DibHeaderDraft,
  dibSize: number | null,
  dibTruncated: boolean
): BmpDibHeader => ({
  ...draft,
  headerKind: describeDibKind(dibSize),
  compressionName: describeCompression(draft.compression),
  colorSpaceTypeName: describeColorSpaceType(draft.colorSpaceType),
  intentName: describeIntent(draft.intent),
  profile: null,
  truncated: dibTruncated
});
export const parseDibHeader = async (
  bytes: Uint8Array,
  fileSize: number,
  ensureBytes: (required: number) => Promise<Uint8Array>,
  pushIssue: (message: string) => void
): Promise<ParsedDibHeader> => {
  let dibSize = readUint32le(bytes, FILE_HEADER_SIZE);
  let headerBytes = bytes;
  if (dibSize == null) {
    if (fileSize >= FILE_HEADER_SIZE) pushIssue("DIB header size field missing (file truncated).");
    dibSize = null;
  } else if (dibSize < 12) {
    pushIssue(`DIB header size is too small (${dibSize}).`);
  } else if (dibSize > MAX_PREFIX_BYTES) {
    pushIssue(`DIB header size is unusually large (${dibSize}); refusing to read full prefix.`);
  }
  const dibEnd = dibSize != null ? FILE_HEADER_SIZE + dibSize : FILE_HEADER_SIZE;
  let haveDibBytes = false;
  if (dibSize != null) {
    headerBytes = await ensureBytes(dibEnd);
    haveDibBytes = headerBytes.length >= dibEnd;
  }
  const dibTruncated = dibSize != null ? !haveDibBytes || dibEnd > fileSize : true;
  if (dibSize != null && dibEnd > fileSize) {
    pushIssue("DIB header truncated (not enough bytes in file).");
  }
  const draft = createDibHeaderDraft(dibSize);
  let masksAfterHeaderBytes = 0;
  if (dibSize != null && dibSize >= 12 && dibSize < 40) {
    readCoreDibHeader(headerBytes, draft);
  } else if (dibSize != null && dibSize >= 40) {
    readInfoDibBase(headerBytes, draft);
    readHeaderContainedMasks(headerBytes, dibSize, draft);
    const bitfieldResult = await readExtraBitfieldMasks(headerBytes, dibSize, draft, fileSize, ensureBytes, pushIssue);
    headerBytes = bitfieldResult.headerBytes;
    masksAfterHeaderBytes = bitfieldResult.masksAfterHeaderBytes;
    readColorSpaceFields(headerBytes, dibSize, draft);
    readProfileFields(headerBytes, dibSize, draft);
  }
  validateDibHeaderDraft(draft, pushIssue);
  return {
    dibSize,
    dibHeader: completeDibHeader(draft, dibSize, dibTruncated),
    masksAfterHeaderBytes
  };
};
