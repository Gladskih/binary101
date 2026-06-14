"use strict";
import type { MpegPsParseResult } from "./types.js";
import { ChunkedFileReader } from "./chunked-file-reader.js";
import { parseMpeg2PackHeader } from "./pack-header.js";
import { parseProgramStreamMap } from "./program-stream-map.js";
import { createMpegPsScanState, finalizeMpegPsScanResult, getOrCreateStream } from "./scan-state.js";
import { parseSystemHeader } from "./system-header.js";
import { decodeTimestamp33 } from "./timestamps.js";
const PACK_START_CODE = 0x000001ba;
const SYSTEM_HEADER_START_CODE = 0x000001bb;
const PROGRAM_STREAM_MAP_START_CODE = 0x000001bc;
const PROGRAM_END_CODE = 0x000001b9;
const CHUNK_SIZE = 1024 * 1024;
const CHUNK_OVERLAP = 64;
const MAX_ISSUES = 200;
const formatOffsetHex = (offset: number): string => `0x${offset.toString(16)}`;
const formatByteHex = (value: number): string => `0x${value.toString(16).padStart(2, "0")}`;
const readUint16be = (bytes: Uint8Array, offset: number): number =>
  ((bytes[offset] ?? 0) << 8) | (bytes[offset + 1] ?? 0);
const isPacketStartCodeByte = (code: number): boolean => {
  if (code === 0xba || code === 0xbb || code === 0xbc || code === 0xb9) return true;
  if (code === 0xbd || code === 0xbe || code === 0xbf) return true;
  if (code >= 0xc0 && code <= 0xef) return true;
  if (code >= 0xf0 && code <= 0xf8) return true;
  return false;
};
type MpegPsScanContext = {
  fileSize: number;
  reader: ChunkedFileReader;
  state: ReturnType<typeof createMpegPsScanState>;
  pushIssue: (message: string) => void;
  lastScrSeconds: number | null;
};
const createIssueCollector = (issues: string[]): ((message: string) => void) => {
  let omittedIssues = false;
  return (message: string): void => {
    if (issues.length >= MAX_ISSUES) {
      if (!omittedIssues) {
        issues.push("Additional issues were detected but omitted to keep the report readable.");
        omittedIssues = true;
      }
      return;
    }
    issues.push(String(message));
  };
};
const hasBytes = (context: MpegPsScanContext, offset: number, requiredBytes: number): boolean =>
  context.reader.hasBytes(offset, requiredBytes);
const ensureBytes = async (context: MpegPsScanContext, offset: number, requiredBytes: number): Promise<boolean> =>
  context.reader.ensureBytes(offset, requiredBytes);
const findNextStartCode = async (context: MpegPsScanContext, offset: number): Promise<number | null> => {
  let cursor = offset;
  while (cursor + 4 <= context.fileSize) {
    if (!hasBytes(context, cursor, 4) && !(await ensureBytes(context, cursor, 4))) return null;
    const local = cursor - context.reader.chunkBase;
    const bytes = context.reader.chunkBytes;
    for (let i = local; i + 4 <= bytes.length; i += 1) {
      if (
        bytes[i] === 0x00 &&
        bytes[i + 1] === 0x00 &&
        bytes[i + 2] === 0x01 &&
        isPacketStartCodeByte(bytes[i + 3] ?? 0)
      ) {
        return context.reader.chunkBase + i;
      }
    }
    cursor = context.reader.chunkBase + bytes.length - 3;
  }
  return null;
};
const recordScr = (context: MpegPsScanContext, scrSeconds: number): void => {
  const scr = context.state.packHeaders.scr;
  scr.count += 1;
  scr.firstSeconds = scr.firstSeconds ?? scrSeconds;
  scr.lastSeconds = scrSeconds;
  scr.minSeconds = scr.minSeconds == null ? scrSeconds : Math.min(scr.minSeconds, scrSeconds);
  scr.maxSeconds = scr.maxSeconds == null ? scrSeconds : Math.max(scr.maxSeconds, scrSeconds);
  if (context.lastScrSeconds != null && scrSeconds < context.lastScrSeconds) scr.backwardsCount += 1;
  context.lastScrSeconds = scrSeconds;
};
const handleMpeg2PackHeader = async (context: MpegPsScanContext, offset: number): Promise<number | null> => {
  const local = offset - context.reader.chunkBase;
  context.state.packHeaders.mpeg2Count += 1;
  const parsed = parseMpeg2PackHeader(context.reader.chunkBytes, local, offset, context.pushIssue);
  if (!parsed.totalSize) {
    context.pushIssue(`Truncated MPEG-2 pack header at ${formatOffsetHex(offset)}.`);
    return null;
  }
  if (parsed.stuffingLength != null) {
    context.state.packHeaders.stuffingBytesTotal += parsed.stuffingLength;
  }
  if (typeof parsed.scrSeconds === "number") recordScr(context, parsed.scrSeconds);
  if (typeof parsed.muxRate === "number") {
    const mux = parsed.muxRate;
    const muxRate = context.state.packHeaders.muxRate;
    muxRate.min = muxRate.min == null ? mux : Math.min(muxRate.min, mux);
    muxRate.max = muxRate.max == null ? mux : Math.max(muxRate.max, mux);
  }
  if (offset + parsed.totalSize > context.fileSize) {
    context.pushIssue(`Pack header claims bytes past end of file at ${formatOffsetHex(offset)}.`);
    return null;
  }
  return offset + parsed.totalSize;
};
const handleMpeg1PackHeader = async (context: MpegPsScanContext, offset: number): Promise<number | null> => {
  context.state.packHeaders.mpeg1Count += 1;
  const hdrSize = 12;
  if (!hasBytes(context, offset, hdrSize) && !(await ensureBytes(context, offset, hdrSize))) {
    context.pushIssue(`Truncated MPEG-1 pack header at ${formatOffsetHex(offset)}.`);
    return null;
  }
  let nextOffset = offset + hdrSize;
  while (nextOffset < context.fileSize) {
    if (!hasBytes(context, nextOffset, 1) && !(await ensureBytes(context, nextOffset, 1))) break;
    if ((context.reader.chunkBytes[nextOffset - context.reader.chunkBase] ?? 0) !== 0xff) break;
    context.state.packHeaders.stuffingBytesTotal += 1;
    nextOffset += 1;
  }
  return nextOffset;
};
const handlePackHeader = async (context: MpegPsScanContext, offset: number): Promise<number | null> => {
  if (!hasBytes(context, offset, 14) && !(await ensureBytes(context, offset, 14))) {
    context.pushIssue(`Truncated pack header at ${formatOffsetHex(offset)}.`);
    return null;
  }
  const b4 = context.reader.chunkBytes[offset - context.reader.chunkBase + 4] ?? 0;
  context.state.packHeaders.totalCount += 1;
  if ((b4 & 0xc0) === 0x40) return handleMpeg2PackHeader(context, offset);
  if ((b4 & 0xf0) === 0x20) return handleMpeg1PackHeader(context, offset);
  context.state.packHeaders.invalidCount += 1;
  context.pushIssue(`Unknown pack header format byte ${formatByteHex(b4)} at ${formatOffsetHex(offset)}.`);
  return findNextStartCode(context, offset + 4);
};
const handleSystemHeader = async (context: MpegPsScanContext, offset: number): Promise<number | null> => {
  if (!hasBytes(context, offset, 6) && !(await ensureBytes(context, offset, 6))) {
    context.pushIssue(`Truncated system header length at ${formatOffsetHex(offset)}.`);
    return null;
  }
  const local = offset - context.reader.chunkBase;
  const headerLength = readUint16be(context.reader.chunkBytes, local + 4);
  const totalSize = 6 + headerLength;
  if (offset + totalSize > context.fileSize) {
    context.state.systemHeaders.totalCount += 1;
    context.state.systemHeaders.truncatedCount += 1;
    context.pushIssue(`Truncated system header at ${formatOffsetHex(offset)} (declared length ${headerLength}).`);
    return null;
  }
  if (!hasBytes(context, offset, totalSize) && !(await ensureBytes(context, offset, totalSize))) {
    context.pushIssue(`Unable to read full system header at ${formatOffsetHex(offset)}.`);
    return null;
  }
  const payloadOffset = offset - context.reader.chunkBase + 6;
  const payload = context.reader.chunkBytes.subarray(payloadOffset, payloadOffset + headerLength);
  const headers = context.state.systemHeaders;
  headers.totalCount += 1;
  headers.lengthTotal += headerLength;
  headers.lengthMin = headers.lengthMin == null ? headerLength : Math.min(headers.lengthMin, headerLength);
  headers.lengthMax = headers.lengthMax == null ? headerLength : Math.max(headers.lengthMax, headerLength);
  if (!headers.firstHeader) headers.firstHeader = parseSystemHeader(payload, context.pushIssue);
  return offset + totalSize;
};
const handleProgramStreamMap = async (context: MpegPsScanContext, offset: number): Promise<number | null> => {
  if (!hasBytes(context, offset, 6) && !(await ensureBytes(context, offset, 6))) {
    context.pushIssue(`Truncated Program Stream Map length at ${formatOffsetHex(offset)}.`);
    return null;
  }
  const mapLength = readUint16be(context.reader.chunkBytes, offset - context.reader.chunkBase + 4);
  const totalSize = 6 + mapLength;
  if (offset + totalSize > context.fileSize) {
    context.state.programStreamMaps.totalCount += 1;
    context.state.programStreamMaps.truncatedCount += 1;
    context.pushIssue(`Truncated Program Stream Map at ${formatOffsetHex(offset)} (declared length ${mapLength}).`);
    return null;
  }
  if (!hasBytes(context, offset, totalSize) && !(await ensureBytes(context, offset, totalSize))) {
    context.pushIssue(`Unable to read full Program Stream Map at ${formatOffsetHex(offset)}.`);
    return null;
  }
  const payloadOffset = offset - context.reader.chunkBase + 6;
  const payload = context.reader.chunkBytes.subarray(payloadOffset, payloadOffset + mapLength);
  const parsed = parseProgramStreamMap(payload, context.pushIssue);
  context.state.programStreamMaps.totalCount += 1;
  if (!context.state.programStreamMaps.firstMap) context.state.programStreamMaps.firstMap = parsed;
  for (const entry of parsed.entries) {
    context.state.programStreamMapTypeCounts.set(
      entry.streamType,
      (context.state.programStreamMapTypeCounts.get(entry.streamType) || 0) + 1
    );
  }
  return offset + totalSize;
};
const recordPts = (stream: ReturnType<typeof getOrCreateStream>, pts: number): void => {
  stream.pts.count += 1;
  stream.pts.first = stream.pts.first ?? pts;
  stream.pts.last = pts;
  stream.pts.min = stream.pts.min == null ? pts : Math.min(stream.pts.min, pts);
  stream.pts.max = stream.pts.max == null ? pts : Math.max(stream.pts.max, pts);
  if (stream.pts.lastSeen != null && pts < stream.pts.lastSeen) stream.pts.backwardsCount += 1;
  stream.pts.lastSeen = pts;
};
const scanPesOptionalHeader = async (
  context: MpegPsScanContext,
  offset: number,
  packetLength: number,
  totalSize: number,
  stream: ReturnType<typeof getOrCreateStream>
): Promise<boolean> => {
  if (packetLength < 3) return true;
  const headerBytes = Math.min(totalSize, 64);
  if (!hasBytes(context, offset, headerBytes) && !(await ensureBytes(context, offset, headerBytes))) return false;
  const local = offset - context.reader.chunkBase;
  const flags0 = context.reader.chunkBytes[local + 6] ?? 0;
  const flags1 = context.reader.chunkBytes[local + 7] ?? 0;
  const headerDataLength = context.reader.chunkBytes[local + 8] ?? 0;
  if ((flags0 & 0xc0) !== 0x80 || packetLength < 3 + headerDataLength || totalSize < 9) return true;
  const ptsDtsFlags = (flags1 >>> 6) & 0x03;
  if ((ptsDtsFlags === 2 || ptsDtsFlags === 3) && headerDataLength >= 5) {
    const pts = decodeTimestamp33(context.reader.chunkBytes, local + 9);
    if (pts != null) recordPts(stream, pts);
    if (ptsDtsFlags === 3 && headerDataLength >= 10) {
      const dts = decodeTimestamp33(context.reader.chunkBytes, local + 14);
      if (dts != null) stream.dtsCount += 1;
    }
  }
  return true;
};
const handlePesPacket = async (
  context: MpegPsScanContext,
  offset: number,
  streamId: number
): Promise<number | null> => {
  if (!hasBytes(context, offset, 6) && !(await ensureBytes(context, offset, 6))) {
    context.pushIssue(`Truncated packet header at ${formatOffsetHex(offset)}.`);
    return null;
  }
  const packetLength = readUint16be(context.reader.chunkBytes, offset - context.reader.chunkBase + 4);
  const stream = getOrCreateStream(context.state, streamId);
  context.state.pesTotalPackets += 1;
  stream.packetCount += 1;
  if (packetLength === 0) {
    stream.packetLengthZeroCount += 1;
    return findNextStartCode(context, offset + 6);
  }
  const totalSize = 6 + packetLength;
  if (offset + totalSize > context.fileSize) {
    context.pushIssue(`PES packet at ${formatOffsetHex(offset)} runs past end of file (length ${packetLength}).`);
    return null;
  }
  stream.declaredBytesTotal += totalSize;
  context.state.pesTotalDeclaredBytes += totalSize;
  if (!(await scanPesOptionalHeader(context, offset, packetLength, totalSize, stream))) return offset + totalSize;
  return offset + totalSize;
};
const dispatchStartCode = async (
  context: MpegPsScanContext,
  offset: number,
  startCode: number,
  code: number
): Promise<number | null> => {
  if (startCode === PACK_START_CODE) return handlePackHeader(context, offset);
  if (startCode === SYSTEM_HEADER_START_CODE) return handleSystemHeader(context, offset);
  if (startCode === PROGRAM_STREAM_MAP_START_CODE) return handleProgramStreamMap(context, offset);
  if (startCode === PROGRAM_END_CODE) {
    context.state.programEndCodeOffset = context.state.programEndCodeOffset ?? offset;
    return null;
  }
  return handlePesPacket(context, offset, code);
};
export async function parseMpegPs(file: File): Promise<MpegPsParseResult | null> {
  if (!file || file.size < 4) return null;
  const prefix = new DataView(await file.slice(0, 4).arrayBuffer());
  if (prefix.getUint32(0, false) !== PACK_START_CODE) return null;
  const issues: string[] = [];
  const context: MpegPsScanContext = {
    fileSize: file.size,
    reader: new ChunkedFileReader(file, CHUNK_SIZE, CHUNK_OVERLAP),
    state: createMpegPsScanState(),
    pushIssue: createIssueCollector(issues),
    lastScrSeconds: null
  };
  let offset = 0;
  while (offset + 4 <= file.size) {
    if (!hasBytes(context, offset, 4) && !(await ensureBytes(context, offset, 4))) break;
    const local = offset - context.reader.chunkBase;
    const [b0 = 0, b1 = 0, b2 = 0] = context.reader.chunkBytes.subarray(local, local + 3);
    if (b0 !== 0x00 || b1 !== 0x00 || b2 !== 0x01) {
      const next = await findNextStartCode(context, offset + 1);
      if (next == null) break;
      context.pushIssue(`Resynced to next start code at ${formatOffsetHex(next)} (from ${formatOffsetHex(offset)}).`);
      offset = next;
      continue;
    }
    const code = context.reader.chunkBytes[local + 3] ?? 0;
    const next = await dispatchStartCode(context, offset, ((b0 << 24) | (b1 << 16) | (b2 << 8) | code) >>> 0, code);
    if (next == null) break;
    offset = next;
  }
  return finalizeMpegPsScanResult(file.size, context.state, issues);
}
