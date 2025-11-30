"use strict";

import { bufferToHex } from "../../binary-utils.js";
import type {
  WebmInfo,
  WebmParseResult,
  WebmSeekHead,
  WebmSegment,
  WebmTrack,
  WebmTrackAudio,
  WebmTrackVideo
} from "./types.js";

const EBML_ID = 0x1a45dfa3;
const SEGMENT_ID = 0x18538067;
const INFO_ID = 0x1549a966;
const TRACKS_ID = 0x1654ae6b;
const TRACK_ENTRY_ID = 0xae;
const SEEK_HEAD_ID = 0x114d9b74;
const SEEK_ENTRY_ID = 0x4dbb;
const SEEK_ID_ID = 0x53ab;
const SEEK_POSITION_ID = 0x53ac;
const CUES_ID = 0x1c53bb6b;
const ATTACHMENTS_ID = 0x1941a469;
const TAGS_ID = 0x1254c367;
const CHAPTERS_ID = 0x1043a770;
const VIDEO_ID = 0xe0;
const AUDIO_ID = 0xe1;

const EBML_DATE_EPOCH_MS = Date.UTC(2001, 0, 1, 0, 0, 0);
const MAX_ELEMENT_HEADER = 12;
const MAX_EBML_HEADER_BYTES = 65536;
const INITIAL_SCAN_BYTES = 1024 * 1024;
const MAX_INFO_BYTES = 256 * 1024;
const MAX_TRACKS_BYTES = 1024 * 1024;
const MAX_SEEK_BYTES = 256 * 1024;

const utf8Decoder = new TextDecoder("utf-8", { fatal: false });

interface Vint {
  length: number;
  value: bigint;
  data: bigint;
  unknown: boolean;
}

interface EbmlElementHeader {
  id: number;
  size: number | null;
  headerSize: number;
  dataOffset: number;
  offset: number;
  sizeUnknown: boolean;
}

interface SegmentScanResult {
  infoHeader: EbmlElementHeader | null;
  tracksHeader: EbmlElementHeader | null;
  seekHeaders: EbmlElementHeader[];
  scanned: Array<{ id: number; offset: number; size: number | null }>;
  issues: string[];
  bytesScanned: number;
  hitLimit: boolean;
}

type Issues = string[];

const describeElement = (id: number): string => {
  switch (id) {
    case EBML_ID:
      return "EBML header";
    case SEGMENT_ID:
      return "Segment";
    case INFO_ID:
      return "Segment Info";
    case TRACKS_ID:
      return "Tracks";
    case TRACK_ENTRY_ID:
      return "TrackEntry";
    case SEEK_HEAD_ID:
      return "SeekHead";
    case VIDEO_ID:
      return "Video";
    case AUDIO_ID:
      return "Audio";
    default:
      return `0x${id.toString(16)}`;
  }
};

const readVint = (dv: DataView, offset: number): Vint | null => {
  if (offset >= dv.byteLength) return null;
  const first = dv.getUint8(offset);
  if (first === 0) return null;
  let length = 1;
  let mask = 0x80;
  while (length <= 8 && (first & mask) === 0) {
    length += 1;
    mask >>= 1;
  }
  if (length > 8) return null;
  if (offset + length > dv.byteLength) return null;
  let value = 0n;
  for (let i = 0; i < length; i += 1) {
    value = (value << 8n) | BigInt(dv.getUint8(offset + i));
  }
  const marker = 1n << BigInt(length * 7);
  const data = value & (marker - 1n);
  const unknown = data === marker - 1n;
  return { length, value, data, unknown };
};

const validateDocTypeCompatibility = (
  issues: Issues,
  docTypeLower: string,
  header: WebmParseResult["ebmlHeader"]
): void => {
  if (!docTypeLower) return;
  if (header.docTypeReadVersion != null && header.docTypeVersion != null) {
    if (header.docTypeReadVersion > header.docTypeVersion) {
      issues.push("DocTypeReadVersion is greater than DocTypeVersion.");
    }
  }
  if (docTypeLower === "webm") {
    if (header.docTypeReadVersion != null && header.docTypeReadVersion > 2) {
      issues.push("DocTypeReadVersion exceeds WebM spec (should be <= 2).");
    }
    if (header.docTypeVersion != null && header.docTypeVersion > 4) {
      issues.push("DocTypeVersion exceeds WebM spec (should be <= 4).");
    }
  }
};

const readElementHeader = (
  dv: DataView,
  cursor: number,
  absoluteOffset: number,
  issues: Issues | null
): EbmlElementHeader | null => {
  const idVint = readVint(dv, cursor);
  if (!idVint) {
    if (issues) issues.push("Unexpected end of data while reading element ID.");
    return null;
  }
  const sizeVint = readVint(dv, cursor + idVint.length);
  if (!sizeVint) {
    if (issues) issues.push(`Unable to read size for element at ${absoluteOffset}.`);
    return null;
  }
  const headerSize = idVint.length + sizeVint.length;
  if (cursor + headerSize > dv.byteLength) {
    if (issues) issues.push(`Element header at ${absoluteOffset} is truncated.`);
    return null;
  }
  const rawSize = sizeVint.data;
  let size: number | null = null;
  if (!sizeVint.unknown) {
    if (rawSize > BigInt(Number.MAX_SAFE_INTEGER)) {
      size = null;
      if (issues) issues.push(`Element at ${absoluteOffset} declares an oversized length.`);
    } else {
      size = Number(rawSize);
    }
  }
  return {
    id: Number(idVint.value),
    size,
    headerSize,
    dataOffset: absoluteOffset + headerSize,
    offset: absoluteOffset,
    sizeUnknown: sizeVint.unknown
  };
};

const clampReadLength = (
  fileSize: number,
  offset: number,
  declaredSize: number | null,
  cap: number
): { length: number; truncated: boolean } => {
  const maxAvailable = Math.max(0, fileSize - offset);
  const desired = declaredSize == null ? cap : Math.min(declaredSize, cap);
  const length = Math.min(desired, maxAvailable);
  const truncated = declaredSize != null && declaredSize > length;
  return { length, truncated };
};

const toSafeNumber = (value: bigint, issues: Issues, label: string): number | null => {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    issues.push(`${label} is too large to represent precisely.`);
    return null;
  }
  return Number(value);
};

const readUnsigned = (
  dv: DataView,
  offset: number,
  length: number,
  issues: Issues,
  label: string
): bigint | null => {
  if (length <= 0 || offset + length > dv.byteLength) {
    issues.push(`${label} is truncated or missing.`);
    return null;
  }
  let value = 0n;
  for (let i = 0; i < length; i += 1) {
    value = (value << 8n) | BigInt(dv.getUint8(offset + i));
  }
  return value;
};

const readFloat = (
  dv: DataView,
  offset: number,
  length: number,
  issues: Issues,
  label: string
): number | null => {
  if (offset + length > dv.byteLength) {
    issues.push(`${label} is truncated or missing.`);
    return null;
  }
  if (length === 4) return dv.getFloat32(offset, false);
  if (length === 8) return dv.getFloat64(offset, false);
  issues.push(`${label} uses unsupported float size ${length}.`);
  return null;
};

const readUtf8 = (dv: DataView, offset: number, length: number): string => {
  const slice = new Uint8Array(dv.buffer, dv.byteOffset + offset, Math.max(0, Math.min(length, dv.byteLength - offset)));
  return utf8Decoder.decode(slice);
};

const readDate = (
  dv: DataView,
  offset: number,
  length: number,
  issues: Issues
): string | null => {
  if (length !== 8 || offset + length > dv.byteLength) {
    issues.push("DateUTC field is truncated or uses unsupported size.");
    return null;
  }
  const value = dv.getBigInt64(offset, false);
  const msOffset = value / 1000000n;
  if (msOffset > BigInt(Number.MAX_SAFE_INTEGER) || msOffset < BigInt(-Number.MAX_SAFE_INTEGER)) {
    issues.push("DateUTC is outside representable range.");
    return null;
  }
  const date = new Date(EBML_DATE_EPOCH_MS + Number(msOffset));
  return date.toISOString();
};

const parseEbmlHeader = async (
  file: File,
  header: EbmlElementHeader,
  issues: Issues
): Promise<{ ebmlHeader: WebmParseResult["ebmlHeader"]; docType: string | null }> => {
  const { length, truncated } = clampReadLength(file.size, header.dataOffset, header.size, MAX_EBML_HEADER_BYTES);
  const dv = new DataView(await file.slice(header.dataOffset, header.dataOffset + length).arrayBuffer());
  const limit = header.size != null ? Math.min(header.size, dv.byteLength) : dv.byteLength;
  if (truncated) issues.push("EBML header is truncated; parsed fields may be incomplete.");
  const ebmlHeader: WebmParseResult["ebmlHeader"] = {
    docType: null,
    docTypeVersion: null,
    docTypeReadVersion: null,
    ebmlVersion: null,
    ebmlReadVersion: null,
    maxIdLength: null,
    maxSizeLength: null
  };
  let cursor = 0;
  while (cursor < limit) {
    const child = readElementHeader(dv, cursor, header.dataOffset + cursor, issues);
    if (!child || child.headerSize === 0) break;
    const dataStart = cursor + child.headerSize;
    const available = Math.min(child.size ?? 0, limit - dataStart);
    if (child.id === 0x4282 && available > 0) {
      ebmlHeader.docType = readUtf8(dv, dataStart, available).trim() || null;
    } else if (child.id === 0x4287) {
      const value = readUnsigned(dv, dataStart, available, issues, "DocTypeVersion");
      ebmlHeader.docTypeVersion = value != null ? Number(value) : null;
    } else if (child.id === 0x4285) {
      const value = readUnsigned(dv, dataStart, available, issues, "DocTypeReadVersion");
      ebmlHeader.docTypeReadVersion = value != null ? Number(value) : null;
    } else if (child.id === 0x4286) {
      const value = readUnsigned(dv, dataStart, available, issues, "EBMLVersion");
      ebmlHeader.ebmlVersion = value != null ? Number(value) : null;
    } else if (child.id === 0x42f7) {
      const value = readUnsigned(dv, dataStart, available, issues, "EBMLReadVersion");
      ebmlHeader.ebmlReadVersion = value != null ? Number(value) : null;
    } else if (child.id === 0x42f2) {
      const value = readUnsigned(dv, dataStart, available, issues, "EBMLMaxIDLength");
      ebmlHeader.maxIdLength = value != null ? Number(value) : null;
    } else if (child.id === 0x42f3) {
      const value = readUnsigned(dv, dataStart, available, issues, "EBMLMaxSizeLength");
      ebmlHeader.maxSizeLength = value != null ? Number(value) : null;
    }
    if (child.size == null || child.size === 0) break;
    cursor += child.headerSize + (child.size ?? 0);
  }
  return { ebmlHeader, docType: ebmlHeader.docType };
};

const scanSegment = async (
  file: File,
  segment: EbmlElementHeader,
  issues: Issues,
  scanLimit: number
): Promise<SegmentScanResult> => {
  const maxAvailable = Math.max(0, file.size - segment.dataOffset);
  const readLength = Math.min(scanLimit, segment.size ?? maxAvailable);
  const dv = new DataView(await file.slice(segment.dataOffset, segment.dataOffset + readLength).arrayBuffer());
  const result: SegmentScanResult = {
    infoHeader: null,
    tracksHeader: null,
    seekHeaders: [],
    scanned: [],
    issues: [],
    bytesScanned: readLength,
    hitLimit: segment.size != null ? readLength < segment.size : readLength < maxAvailable
  };
  let cursor = 0;
  const limit = Math.min(readLength, segment.size ?? readLength);
  while (cursor < limit) {
    const header = readElementHeader(dv, cursor, segment.dataOffset + cursor, result.issues);
    if (!header || header.headerSize === 0) break;
    result.scanned.push({ id: header.id, offset: header.offset, size: header.size });
    if (header.id === INFO_ID && !result.infoHeader) result.infoHeader = header;
    if (header.id === TRACKS_ID && !result.tracksHeader) result.tracksHeader = header;
    if (header.id === SEEK_HEAD_ID) result.seekHeaders.push(header);
    if (header.size == null || header.sizeUnknown) break;
    const next = cursor + header.headerSize + header.size;
    if (next <= cursor) break;
    cursor = next;
  }
  issues.push(...result.issues);
  return result;
};

const parseSeekHead = async (
  file: File,
  seekHead: EbmlElementHeader,
  segmentDataStart: number,
  issues: Issues
): Promise<WebmSeekHead> => {
  const { length, truncated } = clampReadLength(file.size, seekHead.dataOffset, seekHead.size, MAX_SEEK_BYTES);
  const dv = new DataView(await file.slice(seekHead.dataOffset, seekHead.dataOffset + length).arrayBuffer());
  const limit = seekHead.size != null ? Math.min(seekHead.size, dv.byteLength) : dv.byteLength;
  const entries: WebmSeekHead["entries"] = [];
  let cursor = 0;
  while (cursor < limit) {
    const entryHeader = readElementHeader(dv, cursor, seekHead.dataOffset + cursor, issues);
    if (!entryHeader || entryHeader.headerSize === 0) break;
    const dataStart = cursor + entryHeader.headerSize;
    const available = Math.min(entryHeader.size ?? 0, limit - dataStart);
    if (entryHeader.id === SEEK_ENTRY_ID && available > 0) {
      let id = 0;
      let position: number | null = null;
      let absoluteOffset: number | null = null;
      let innerCursor = dataStart;
      const entryEnd = dataStart + available;
      while (innerCursor < entryEnd) {
        const innerHeader = readElementHeader(dv, innerCursor, seekHead.dataOffset + innerCursor, issues);
        if (!innerHeader || innerHeader.headerSize === 0 || innerHeader.size == null) break;
        const innerData = innerCursor + innerHeader.headerSize;
        const innerAvailable = Math.min(innerHeader.size, entryEnd - innerData);
        if (innerHeader.id === SEEK_ID_ID && innerAvailable > 0) {
          id = new Uint8Array(dv.buffer, dv.byteOffset + innerData, innerAvailable).reduce(
            (acc, byte) => (acc << 8) | byte,
            0
          );
        } else if (innerHeader.id === SEEK_POSITION_ID && innerAvailable > 0) {
          const posValue = readUnsigned(dv, innerData, innerAvailable, issues, "SeekPosition");
          if (posValue != null) {
            position = toSafeNumber(posValue, issues, "SeekPosition");
            if (position != null) {
              absoluteOffset = segmentDataStart + position;
            }
          }
        }
        innerCursor += innerHeader.headerSize + innerHeader.size;
      }
      entries.push({
        id,
        name: describeElement(id),
        position,
        absoluteOffset
      });
    }
    if (entryHeader.size == null) break;
    cursor += entryHeader.headerSize + entryHeader.size;
  }
  return { entries, truncated: truncated || (seekHead.size != null && length < seekHead.size) };
};

const parseInfo = async (
  file: File,
  infoHeader: EbmlElementHeader,
  timecodeScaleFallback: number,
  issues: Issues
): Promise<WebmInfo> => {
  const { length, truncated } = clampReadLength(file.size, infoHeader.dataOffset, infoHeader.size, MAX_INFO_BYTES);
  const dv = new DataView(await file.slice(infoHeader.dataOffset, infoHeader.dataOffset + length).arrayBuffer());
  const limit = infoHeader.size != null ? Math.min(infoHeader.size, dv.byteLength) : dv.byteLength;
  const info: WebmInfo = {
    timecodeScale: timecodeScaleFallback,
    duration: null,
    durationSeconds: null,
    muxingApp: null,
    writingApp: null,
    title: null,
    dateUtc: null,
    segmentUid: null
  };
  let cursor = 0;
  while (cursor < limit) {
    const child = readElementHeader(dv, cursor, infoHeader.dataOffset + cursor, issues);
    if (!child || child.headerSize === 0) break;
    const dataStart = cursor + child.headerSize;
    const available = Math.min(child.size ?? 0, limit - dataStart);
    if (child.id === 0x2ad7b1 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "TimecodeScale");
      info.timecodeScale = value != null ? Number(value) : timecodeScaleFallback;
    } else if (child.id === 0x4489 && available > 0) {
      info.duration = readFloat(dv, dataStart, available, issues, "Duration");
    } else if (child.id === 0x4d80 && available > 0) {
      info.muxingApp = readUtf8(dv, dataStart, available);
    } else if (child.id === 0x5741 && available > 0) {
      info.writingApp = readUtf8(dv, dataStart, available);
    } else if (child.id === 0x7ba9 && available > 0) {
      info.title = readUtf8(dv, dataStart, available);
    } else if (child.id === 0x4461 && available > 0) {
      info.dateUtc = readDate(dv, dataStart, available, issues);
    } else if (child.id === 0x73a4 && available > 0) {
      const uidBytes = new Uint8Array(
        dv.buffer,
        dv.byteOffset + dataStart,
        Math.min(available, dv.byteLength - dataStart)
      );
      info.segmentUid = bufferToHex(uidBytes);
    }
    if (child.size == null) break;
    cursor += child.headerSize + child.size;
  }
  if (info.duration != null && info.timecodeScale != null) {
    info.durationSeconds = (info.duration * info.timecodeScale) / 1e9;
  }
  if (truncated) issues.push("Segment Info section is truncated; some fields may be missing.");
  return info;
};

const parseVideo = (
  dv: DataView,
  offset: number,
  size: number,
  absoluteOffset: number,
  issues: Issues
): WebmTrackVideo => {
  const video: WebmTrackVideo = {
    pixelWidth: null,
    pixelHeight: null,
    displayWidth: null,
    displayHeight: null,
    stereoMode: null,
    alphaMode: null
  };
  let cursor = 0;
  const limit = Math.min(size, dv.byteLength - offset);
  const pixelCrop = { top: null as number | null, bottom: null as number | null, left: null as number | null, right: null as number | null };
  while (cursor < limit) {
    const header = readElementHeader(dv, offset + cursor, absoluteOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    const dataStart = offset + cursor + header.headerSize;
    const available = Math.min(header.size ?? 0, limit - (cursor + header.headerSize));
    if (header.id === 0xb0 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "PixelWidth");
      video.pixelWidth = value != null ? Number(value) : null;
    } else if (header.id === 0xba && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "PixelHeight");
      video.pixelHeight = value != null ? Number(value) : null;
    } else if (header.id === 0x54b0 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "DisplayWidth");
      video.displayWidth = value != null ? Number(value) : null;
    } else if (header.id === 0x54ba && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "DisplayHeight");
      video.displayHeight = value != null ? Number(value) : null;
    } else if (header.id === 0x53b8 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "StereoMode");
      video.stereoMode = value != null ? Number(value) : null;
    } else if (header.id === 0x53c0 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "AlphaMode");
      video.alphaMode = value != null ? Number(value) : null;
    } else if (header.id === 0x54aa && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "PixelCropBottom");
      pixelCrop.bottom = value != null ? Number(value) : null;
    } else if (header.id === 0x54bb && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "PixelCropTop");
      pixelCrop.top = value != null ? Number(value) : null;
    } else if (header.id === 0x54cc && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "PixelCropLeft");
      pixelCrop.left = value != null ? Number(value) : null;
    } else if (header.id === 0x54dd && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "PixelCropRight");
      pixelCrop.right = value != null ? Number(value) : null;
    }
    if (header.size == null) break;
    cursor += header.headerSize + header.size;
  }
  if (pixelCrop.top !== null || pixelCrop.bottom !== null || pixelCrop.left !== null || pixelCrop.right !== null) {
    video.pixelCrop = pixelCrop;
  }
  return video;
};

const parseAudio = (
  dv: DataView,
  offset: number,
  size: number,
  absoluteOffset: number,
  issues: Issues
): WebmTrackAudio => {
  const audio: WebmTrackAudio = {
    samplingFrequency: null,
    outputSamplingFrequency: null,
    channels: null,
    bitDepth: null
  };
  let cursor = 0;
  const limit = Math.min(size, dv.byteLength - offset);
  while (cursor < limit) {
    const header = readElementHeader(dv, offset + cursor, absoluteOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    const dataStart = offset + cursor + header.headerSize;
    const available = Math.min(header.size ?? 0, limit - (cursor + header.headerSize));
    if (header.id === 0xb5 && available > 0) {
      audio.samplingFrequency = readFloat(dv, dataStart, available, issues, "SamplingFrequency");
    } else if (header.id === 0x78b5 && available > 0) {
      audio.outputSamplingFrequency = readFloat(dv, dataStart, available, issues, "OutputSamplingFrequency");
    } else if (header.id === 0x9f && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "Channels");
      audio.channels = value != null ? Number(value) : null;
    } else if (header.id === 0x6264 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "BitDepth");
      audio.bitDepth = value != null ? Number(value) : null;
    }
    if (header.size == null) break;
    cursor += header.headerSize + header.size;
  }
  return audio;
};

const describeTrackType = (trackType: number | null): string => {
  if (trackType === 1) return "Video";
  if (trackType === 2) return "Audio";
  if (trackType === 3) return "Complex";
  if (trackType === 0x10) return "Logo";
  if (trackType === 0x11) return "Subtitle";
  if (trackType === 0x12) return "Buttons";
  if (trackType === 0x20) return "Metadata";
  return "Unknown";
};

const parseTrackEntry = (
  dv: DataView,
  offset: number,
  size: number,
  absoluteOffset: number,
  issues: Issues
): WebmTrack => {
  const track: WebmTrack = {
    trackNumber: null,
    trackUid: null,
    trackType: null,
    trackTypeLabel: "Unknown",
    name: null,
    language: null,
    codecId: null,
    codecName: null,
    defaultDuration: null,
    defaultDurationFps: null,
    codecPrivateSize: null,
    flagEnabled: null,
    flagDefault: null,
    flagForced: null,
    flagLacing: null,
    video: null,
    audio: null
  };
  let cursor = 0;
  const limit = Math.min(size, dv.byteLength - offset);
  while (cursor < limit) {
    const header = readElementHeader(dv, offset + cursor, absoluteOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    const dataStart = offset + cursor + header.headerSize;
    const available = Math.min(header.size ?? 0, limit - (cursor + header.headerSize));
    if (header.id === 0xd7 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "TrackNumber");
      track.trackNumber = value != null ? Number(value) : null;
    } else if (header.id === 0x73c5 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "TrackUID");
      if (value != null) {
        track.trackUid =
          value > BigInt(Number.MAX_SAFE_INTEGER) ? value.toString() : Number(value);
      }
    } else if (header.id === 0x83 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "TrackType");
      track.trackType = value != null ? Number(value) : null;
      track.trackTypeLabel = describeTrackType(track.trackType);
    } else if (header.id === 0x86 && available > 0) {
      track.codecId = readUtf8(dv, dataStart, available);
    } else if (header.id === 0x258688 && available > 0) {
      track.codecName = readUtf8(dv, dataStart, available);
    } else if (header.id === 0x536e && available > 0) {
      track.name = readUtf8(dv, dataStart, available);
    } else if (header.id === 0x22b59c && available > 0) {
      track.language = readUtf8(dv, dataStart, available);
    } else if (header.id === 0x23e383 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "DefaultDuration");
      if (value != null) {
        let numeric: number | null = null;
        const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
        if (value > maxSafe) {
          if (header.size != null && header.size <= 8) {
            numeric = Number(value & 0xffffffffn);
            issues.push("DefaultDuration is larger than safe range; using low 32 bits.");
          } else {
            issues.push("DefaultDuration is too large to represent precisely.");
          }
        } else {
          numeric = Number(value);
        }
        track.defaultDuration = numeric;
        if (numeric && numeric > 0) {
          track.defaultDurationFps = Math.round((1e9 / numeric) * 100) / 100;
        }
      }
    } else if (header.id === 0xb9 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "FlagEnabled");
      track.flagEnabled = value != null ? Number(value) !== 0 : null;
    } else if (header.id === 0x88 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "FlagDefault");
      track.flagDefault = value != null ? Number(value) !== 0 : null;
    } else if (header.id === 0x55aa && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "FlagForced");
      track.flagForced = value != null ? Number(value) !== 0 : null;
    } else if (header.id === 0x9c && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "FlagLacing");
      track.flagLacing = value != null ? Number(value) !== 0 : null;
    } else if (header.id === 0x63a2) {
      track.codecPrivateSize = header.size;
    } else if (header.id === VIDEO_ID && header.size != null) {
      track.video = parseVideo(dv, dataStart, header.size, header.dataOffset, issues);
    } else if (header.id === AUDIO_ID && header.size != null) {
      track.audio = parseAudio(dv, dataStart, header.size, header.dataOffset, issues);
    }
    if (header.size == null) break;
    cursor += header.headerSize + header.size;
  }
  if (!track.language) {
    track.language = "und";
    track.languageDefaulted = true;
  }
  return track;
};

const parseTracks = async (
  file: File,
  tracksHeader: EbmlElementHeader,
  issues: Issues
): Promise<WebmTrack[]> => {
  const { length, truncated } = clampReadLength(file.size, tracksHeader.dataOffset, tracksHeader.size, MAX_TRACKS_BYTES);
  const dv = new DataView(await file.slice(tracksHeader.dataOffset, tracksHeader.dataOffset + length).arrayBuffer());
  const limit = tracksHeader.size != null ? Math.min(tracksHeader.size, dv.byteLength) : dv.byteLength;
  const tracks: WebmTrack[] = [];
  let cursor = 0;
  while (cursor < limit) {
    const header = readElementHeader(dv, cursor, tracksHeader.dataOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    if (header.id === TRACK_ENTRY_ID && header.size != null) {
      const dataStart = cursor + header.headerSize;
      const available = Math.min(header.size, limit - dataStart);
      const track = parseTrackEntry(
        dv,
        dataStart,
        available,
        tracksHeader.dataOffset + dataStart,
        issues
      );
      tracks.push(track);
    }
    if (header.size == null) break;
    cursor += header.headerSize + (header.size ?? 0);
  }
  if (truncated) issues.push("Tracks section is truncated; some tracks may be missing.");
  return tracks;
};

const pickElement = (
  scan: SegmentScanResult,
  seek: WebmSeekHead | null,
  targetId: number
): EbmlElementHeader | null => {
  if (targetId === INFO_ID && scan.infoHeader) return scan.infoHeader;
  if (targetId === TRACKS_ID && scan.tracksHeader) return scan.tracksHeader;
  const candidate = seek?.entries.find(entry => entry.id === targetId && entry.absoluteOffset != null);
  if (!candidate || candidate.absoluteOffset == null) return null;
  const offset = candidate.absoluteOffset;
  return { id: targetId, size: null, headerSize: 0, dataOffset: offset, offset, sizeUnknown: true };
};

const parseSegment = async (
  file: File,
  segmentHeader: EbmlElementHeader,
  issues: Issues,
  docTypeLower: string
): Promise<WebmSegment> => {
  const segmentSize = segmentHeader.size ?? Math.max(0, file.size - segmentHeader.dataOffset);
  const segment: WebmSegment = {
    offset: segmentHeader.offset,
    size: segmentHeader.size,
    dataOffset: segmentHeader.dataOffset,
    dataSize: segmentSize,
    info: null,
    tracks: [],
    seekHead: null,
    scannedElements: [],
    scanLimit: Math.min(INITIAL_SCAN_BYTES, segmentSize)
  };

  const initialLimit = Math.min(INITIAL_SCAN_BYTES, segmentSize);
  const initialScan = await scanSegment(file, segmentHeader, issues, initialLimit);
  let scan = initialScan;
  if ((!initialScan.infoHeader || !initialScan.tracksHeader) && segmentSize > initialLimit) {
    const fullScan = await scanSegment(file, segmentHeader, issues, segmentSize);
    scan = fullScan;
    segment.scanLimit = fullScan.bytesScanned;
  } else {
    segment.scanLimit = initialScan.bytesScanned;
  }
  segment.scannedElements = scan.scanned;
  let seekHead: WebmSeekHead | null = null;
  const [firstSeek] = scan.seekHeaders;
  if (firstSeek) {
    seekHead = await parseSeekHead(file, firstSeek, segmentHeader.dataOffset, issues);
    segment.seekHead = seekHead;
  }

  const infoHeader =
    scan.infoHeader ||
    pickElement(scan, seekHead, INFO_ID) ||
    null;
  if (infoHeader) {
    const resolved = infoHeader.headerSize
      ? infoHeader
      : await readElementAt(file, infoHeader.offset, issues);
    if (resolved && resolved.id === INFO_ID) {
      segment.info = await parseInfo(file, resolved, 1000000, issues);
    }
  }

  const tracksHeader =
    scan.tracksHeader ||
    pickElement(scan, seekHead, TRACKS_ID) ||
    null;
  if (tracksHeader) {
    const resolved = tracksHeader.headerSize
      ? tracksHeader
      : await readElementAt(file, tracksHeader.offset, issues);
    if (resolved && resolved.id === TRACKS_ID) {
      segment.tracks = await parseTracks(file, resolved, issues);
    }
  }

  if ((!scan.infoHeader || !scan.tracksHeader) && scan.hitLimit && segmentHeader.size == null) {
    issues.push(
      `Segment scanning stopped after ${scan.bytesScanned} bytes; segment size is unknown so some metadata may be missing.`
    );
  }

  const ids = new Set(scan.scanned.map(element => element.id));
  const hasCues = ids.has(CUES_ID);
  const hasAttachments = ids.has(ATTACHMENTS_ID);
  const hasTags = ids.has(TAGS_ID);
  const hasChapters = ids.has(CHAPTERS_ID);
  if (!hasCues) {
    issues.push("Cues element not found; seeking metadata may be missing.");
  }
  if (docTypeLower === "webm") {
    if (hasAttachments) issues.push("Attachments element present; invalid for WebM.");
    if (hasTags) issues.push("Tags element present; invalid for WebM.");
    if (hasChapters) issues.push("Chapters element present; invalid for WebM.");
  }

  return segment;
};

const readElementAt = async (
  file: File,
  offset: number,
  issues: Issues
): Promise<EbmlElementHeader | null> => {
  if (offset >= file.size) {
    issues.push(`Element offset ${offset} is beyond file size.`);
    return null;
  }
  const length = Math.min(MAX_ELEMENT_HEADER, file.size - offset);
  const dv = new DataView(await file.slice(offset, offset + length).arrayBuffer());
  return readElementHeader(dv, 0, offset, issues);
};

export async function parseWebm(file: File): Promise<WebmParseResult | null> {
  if (file.size < 4) return null;
  const prefix = new DataView(await file.slice(0, Math.min(file.size, 1024)).arrayBuffer());
  if (prefix.getUint32(0, false) !== EBML_ID) return null;
  const issues: Issues = [];
  const ebmlHeader = await readElementAt(file, 0, issues);
  if (!ebmlHeader || ebmlHeader.id !== EBML_ID) return null;
  const { ebmlHeader: headerInfo, docType } = await parseEbmlHeader(file, ebmlHeader, issues);
  const docTypeLower = docType ? docType.toLowerCase() : "";
  validateDocTypeCompatibility(issues, docTypeLower, headerInfo);
  const segmentOffset =
    ebmlHeader.size != null ? ebmlHeader.dataOffset + ebmlHeader.size : ebmlHeader.dataOffset;
  const segmentHeader = await readElementAt(file, segmentOffset, issues);
  if (!segmentHeader || segmentHeader.id !== SEGMENT_ID) {
    issues.push("Segment element not found after EBML header.");
    return {
      isWebm: docType?.toLowerCase() === "webm",
      isMatroska: docType?.toLowerCase() === "matroska",
      docType: docType || null,
      ebmlHeader: headerInfo,
      segment: null,
      issues
    };
  }
  const segment = await parseSegment(file, segmentHeader, issues, docTypeLower);
  const lowerDoc = docTypeLower;
  return {
    isWebm: lowerDoc === "webm",
    isMatroska: lowerDoc === "matroska",
    docType: docType || null,
    ebmlHeader: headerInfo,
    segment,
    issues
  };
}

export const buildWebmLabel = (parsed: WebmParseResult | null | undefined): string | null => {
  if (!parsed || !parsed.segment) return null;
  const prefix = parsed.isWebm
    ? "WebM"
    : parsed.isMatroska
      ? "Matroska"
      : parsed.docType
        ? `Matroska (${parsed.docType})`
        : "Matroska/WebM";
  const tracks = parsed.segment.tracks || [];
  const video = tracks.find(track => track.trackType === 1);
  const audio = tracks.find(track => track.trackType === 2);
  const parts: string[] = [];
  if (video) {
    const videoParts: string[] = [];
    if (video.codecId) videoParts.push(video.codecId);
    if (video.video?.pixelWidth && video.video?.pixelHeight) {
      videoParts.push(`${video.video.pixelWidth}x${video.video.pixelHeight}`);
    }
    if (video.defaultDurationFps) videoParts.push(`${video.defaultDurationFps} fps`);
    parts.push(`video: ${videoParts.join(", ") || "track"}`);
  }
  if (audio) {
    const audioParts: string[] = [];
    if (audio.codecId) audioParts.push(audio.codecId);
    if (audio.audio?.samplingFrequency) {
      const rate = Math.round(audio.audio.samplingFrequency);
      audioParts.push(`${rate} Hz`);
    }
    if (audio.audio?.channels) audioParts.push(`${audio.audio.channels} ch`);
    parts.push(`audio: ${audioParts.join(", ") || "track"}`);
  }
  const suffix = parts.length ? ` (${parts.join("; ")})` : "";
  return `${prefix}${suffix}`;
};
