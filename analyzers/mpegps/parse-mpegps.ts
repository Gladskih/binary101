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
export async function parseMpegPs(file: File): Promise<MpegPsParseResult | null> {
  if (!file || file.size < 4) return null;
  const prefix = new DataView(await file.slice(0, 4).arrayBuffer());
  if (prefix.getUint32(0, false) !== PACK_START_CODE) return null;
  const issues: string[] = [];
  let omittedIssues = false;
  const pushIssue = (message: string): void => {
    if (issues.length >= MAX_ISSUES) {
      if (!omittedIssues) {
        issues.push("Additional issues were detected but omitted to keep the report readable.");
        omittedIssues = true;
      }
      return;
    }
    issues.push(String(message));
  };
  const state = createMpegPsScanState();
  const reader = new ChunkedFileReader(file, CHUNK_SIZE, CHUNK_OVERLAP);
  const ensureBytes = async (offset: number, requiredBytes: number): Promise<boolean> =>
    reader.ensureBytes(offset, requiredBytes);
  const findNextStartCode = async (offset: number): Promise<number | null> => {
    let cursor = offset;
    while (cursor + 4 <= file.size) {
      const ok = await ensureBytes(cursor, 4);
      if (!ok) return null;
      const local = cursor - reader.chunkBase;
      const bytes = reader.chunkBytes;
      for (let i = local; i + 4 <= bytes.length; i += 1) {
        if (
          bytes[i] === 0x00 &&
          bytes[i + 1] === 0x00 &&
          bytes[i + 2] === 0x01 &&
          isPacketStartCodeByte(bytes[i + 3] ?? 0)
        ) {
          return reader.chunkBase + i;
        }
      }
      cursor = reader.chunkBase + bytes.length - 3;
    }
    return null;
  };
  let offset = 0;
  let lastScrSeconds: number | null = null;
  while (offset + 4 <= file.size) {
    const ok = await ensureBytes(offset, 4);
    if (!ok) break;
    let local = offset - reader.chunkBase;
    const b0 = reader.chunkBytes[local] ?? 0;
    const b1 = reader.chunkBytes[local + 1] ?? 0;
    const b2 = reader.chunkBytes[local + 2] ?? 0;
    if (b0 !== 0x00 || b1 !== 0x00 || b2 !== 0x01) {
      const next = await findNextStartCode(offset + 1);
      if (next == null) break;
      pushIssue(
        `Resynced to next start code at ${formatOffsetHex(next)} (from ${formatOffsetHex(offset)}).`
      );
      offset = next;
      continue;
    }
    const code = reader.chunkBytes[local + 3] ?? 0;
    const startCode = ((b0 << 24) | (b1 << 16) | (b2 << 8) | code) >>> 0;
    if (startCode === PACK_START_CODE) {
      const hdrOk = await ensureBytes(offset, 14);
      if (!hdrOk) {
        pushIssue(`Truncated pack header at ${formatOffsetHex(offset)}.`);
        break;
      }
      local = offset - reader.chunkBase;
      const b4 = reader.chunkBytes[local + 4] ?? 0;
      state.packHeaders.totalCount += 1;
      if ((b4 & 0xc0) === 0x40) {
        state.packHeaders.mpeg2Count += 1;
        const parsed = parseMpeg2PackHeader(reader.chunkBytes, local, offset, pushIssue);
        if (!parsed.totalSize) {
          pushIssue(`Truncated MPEG-2 pack header at ${formatOffsetHex(offset)}.`);
          break;
        }
        if (parsed.stuffingLength != null) {
          state.packHeaders.stuffingBytesTotal += parsed.stuffingLength;
        }
        if (typeof parsed.scrSeconds === "number") {
          const scrSeconds = parsed.scrSeconds;
          state.packHeaders.scr.count += 1;
          state.packHeaders.scr.firstSeconds = state.packHeaders.scr.firstSeconds ?? scrSeconds;
          state.packHeaders.scr.lastSeconds = scrSeconds;
          state.packHeaders.scr.minSeconds =
            state.packHeaders.scr.minSeconds == null
              ? scrSeconds
              : Math.min(state.packHeaders.scr.minSeconds, scrSeconds);
          state.packHeaders.scr.maxSeconds =
            state.packHeaders.scr.maxSeconds == null
              ? scrSeconds
              : Math.max(state.packHeaders.scr.maxSeconds, scrSeconds);
          if (lastScrSeconds != null && scrSeconds < lastScrSeconds) state.packHeaders.scr.backwardsCount += 1;
          lastScrSeconds = scrSeconds;
        }
        if (typeof parsed.muxRate === "number") {
          const mux = parsed.muxRate;
          state.packHeaders.muxRate.min =
            state.packHeaders.muxRate.min == null ? mux : Math.min(state.packHeaders.muxRate.min, mux);
          state.packHeaders.muxRate.max =
            state.packHeaders.muxRate.max == null ? mux : Math.max(state.packHeaders.muxRate.max, mux);
        }
        if (offset + parsed.totalSize > file.size) {
          pushIssue(`Pack header claims bytes past end of file at ${formatOffsetHex(offset)}.`);
          break;
        }
        offset += parsed.totalSize;
        continue;
      }
      if ((b4 & 0xf0) === 0x20) {
        state.packHeaders.mpeg1Count += 1;
        const hdrSize = 12;
        const ok12 = await ensureBytes(offset, hdrSize);
        if (!ok12) {
          pushIssue(`Truncated MPEG-1 pack header at ${formatOffsetHex(offset)}.`);
          break;
        }
        offset += hdrSize;
        while (offset < file.size) {
          const okStuffing = await ensureBytes(offset, 1);
          if (!okStuffing) break;
          const value = reader.chunkBytes[offset - reader.chunkBase] ?? 0;
          if (value !== 0xff) break;
          state.packHeaders.stuffingBytesTotal += 1;
          offset += 1;
        }
        continue;
      }
      state.packHeaders.invalidCount += 1;
      pushIssue(`Unknown pack header format byte ${formatByteHex(b4)} at ${formatOffsetHex(offset)}.`);
      const next = await findNextStartCode(offset + 4);
      if (next == null) break;
      offset = next;
      continue;
    }
    if (startCode === SYSTEM_HEADER_START_CODE) {
      const okLen = await ensureBytes(offset, 6);
      if (!okLen) {
        pushIssue(`Truncated system header length at ${formatOffsetHex(offset)}.`);
        break;
      }
      local = offset - reader.chunkBase;
      const headerLength = readUint16be(reader.chunkBytes, local + 4);
      const totalSize = 6 + headerLength;
      if (offset + totalSize > file.size) {
        state.systemHeaders.totalCount += 1;
        state.systemHeaders.truncatedCount += 1;
        pushIssue(`Truncated system header at ${formatOffsetHex(offset)} (declared length ${headerLength}).`);
        break;
      }
      const okPayload = await ensureBytes(offset, totalSize);
      if (!okPayload) {
        pushIssue(`Unable to read full system header at ${formatOffsetHex(offset)}.`);
        break;
      }
      local = offset - reader.chunkBase;
      const payload = reader.chunkBytes.subarray(local + 6, local + 6 + headerLength);
      state.systemHeaders.totalCount += 1;
      state.systemHeaders.lengthTotal += headerLength;
      state.systemHeaders.lengthMin =
        state.systemHeaders.lengthMin == null ? headerLength : Math.min(state.systemHeaders.lengthMin, headerLength);
      state.systemHeaders.lengthMax =
        state.systemHeaders.lengthMax == null ? headerLength : Math.max(state.systemHeaders.lengthMax, headerLength);
      if (!state.systemHeaders.firstHeader) {
        state.systemHeaders.firstHeader = parseSystemHeader(payload, pushIssue);
      }
      offset += totalSize;
      continue;
    }

    if (startCode === PROGRAM_STREAM_MAP_START_CODE) {
      const okLen = await ensureBytes(offset, 6);
      if (!okLen) {
        pushIssue(`Truncated Program Stream Map length at ${formatOffsetHex(offset)}.`);
        break;
      }
      local = offset - reader.chunkBase;
      const mapLength = readUint16be(reader.chunkBytes, local + 4);
      const totalSize = 6 + mapLength;
      if (offset + totalSize > file.size) {
        state.programStreamMaps.totalCount += 1;
        state.programStreamMaps.truncatedCount += 1;
        pushIssue(`Truncated Program Stream Map at ${formatOffsetHex(offset)} (declared length ${mapLength}).`);
        break;
      }
      const okPayload = await ensureBytes(offset, totalSize);
      if (!okPayload) {
        pushIssue(`Unable to read full Program Stream Map at ${formatOffsetHex(offset)}.`);
        break;
      }
      local = offset - reader.chunkBase;
      const payload = reader.chunkBytes.subarray(local + 6, local + 6 + mapLength);
      const parsed = parseProgramStreamMap(payload, pushIssue);
      state.programStreamMaps.totalCount += 1;
      if (!state.programStreamMaps.firstMap) state.programStreamMaps.firstMap = parsed;
      for (const entry of parsed.entries) {
        state.programStreamMapTypeCounts.set(
          entry.streamType,
          (state.programStreamMapTypeCounts.get(entry.streamType) || 0) + 1
        );
      }
      offset += totalSize;
      continue;
    }

    if (startCode === PROGRAM_END_CODE) {
      state.programEndCodeOffset = state.programEndCodeOffset ?? offset;
      offset += 4;
      break;
    }

    const okPes = await ensureBytes(offset, 6);
    if (!okPes) {
      pushIssue(`Truncated packet header at ${formatOffsetHex(offset)}.`);
      break;
    }
    const streamId = code;
    local = offset - reader.chunkBase;
    const packetLength = readUint16be(reader.chunkBytes, local + 4);
    const stream = getOrCreateStream(state, streamId);
    state.pesTotalPackets += 1;
    stream.packetCount += 1;

    if (packetLength === 0) {
      stream.packetLengthZeroCount += 1;
      const next = await findNextStartCode(offset + 6);
      if (next == null) break;
      offset = next;
      continue;
    }

    const totalSize = 6 + packetLength;
    if (offset + totalSize > file.size) {
      pushIssue(`PES packet at ${formatOffsetHex(offset)} runs past end of file (length ${packetLength}).`);
      break;
    }

    stream.declaredBytesTotal += totalSize;
    state.pesTotalDeclaredBytes += totalSize;

    const headerOk = await ensureBytes(offset, Math.min(totalSize, 64));
    if (headerOk && packetLength >= 3) {
      local = offset - reader.chunkBase;
      const flags0 = reader.chunkBytes[local + 6] ?? 0;
      const flags1 = reader.chunkBytes[local + 7] ?? 0;
      const headerDataLength = reader.chunkBytes[local + 8] ?? 0;
      if ((flags0 & 0xc0) === 0x80 && packetLength >= 3 + headerDataLength && totalSize >= 9) {
        const ptsDtsFlags = (flags1 >>> 6) & 0x03;
        const optionalStart = local + 9;
        if ((ptsDtsFlags === 2 || ptsDtsFlags === 3) && headerDataLength >= 5) {
          const pts = decodeTimestamp33(reader.chunkBytes, optionalStart);
          if (pts != null) {
            stream.pts.count += 1;
            stream.pts.first = stream.pts.first ?? pts;
            stream.pts.last = pts;
            stream.pts.min = stream.pts.min == null ? pts : Math.min(stream.pts.min, pts);
            stream.pts.max = stream.pts.max == null ? pts : Math.max(stream.pts.max, pts);
            if (stream.pts.lastSeen != null && pts < stream.pts.lastSeen) stream.pts.backwardsCount += 1;
            stream.pts.lastSeen = pts;
          }
          if (ptsDtsFlags === 3 && headerDataLength >= 10) {
            const dts = decodeTimestamp33(reader.chunkBytes, optionalStart + 5);
            if (dts != null) stream.dtsCount += 1;
          }
        }
      }
    }

    offset += totalSize;
  }

  return finalizeMpegPsScanResult(file.size, state, issues);
}
