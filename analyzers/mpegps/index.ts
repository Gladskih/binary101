"use strict";

import type {
  MpegPsParseResult,
  MpegPsProgramStreamMapDetail,
  MpegPsStreamKind,
  MpegPsSystemHeaderDetail
} from "./types.js";

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

const classifyStreamId = (streamId: number): MpegPsStreamKind => {
  if (streamId >= 0xe0 && streamId <= 0xef) return "video";
  if (streamId >= 0xc0 && streamId <= 0xdf) return "audio";
  if (streamId === 0xbd || streamId === 0xbf) return "private";
  if (streamId === 0xbe) return "padding";
  return "other";
};

type MutablePts = {
  count: number;
  first: number | null;
  last: number | null;
  min: number | null;
  max: number | null;
  lastSeen: number | null;
  backwardsCount: number;
};

type MutableStream = {
  streamId: number;
  kind: MpegPsStreamKind;
  packetCount: number;
  packetLengthZeroCount: number;
  declaredBytesTotal: number;
  pts: MutablePts;
  dtsCount: number;
};

const createEmptyPts = (): MutablePts => ({
  count: 0,
  first: null,
  last: null,
  min: null,
  max: null,
  lastSeen: null,
  backwardsCount: 0
});

const decodeTimestamp33 = (bytes: Uint8Array, offset: number): number | null => {
  if (offset + 5 > bytes.length) return null;
  const b0 = bytes[offset] ?? 0;
  const b1 = bytes[offset + 1] ?? 0;
  const b2 = bytes[offset + 2] ?? 0;
  const b3 = bytes[offset + 3] ?? 0;
  const b4 = bytes[offset + 4] ?? 0;

  const markerOk = (b0 & 0x01) !== 0 && (b2 & 0x01) !== 0 && (b4 & 0x01) !== 0;
  if (!markerOk) return null;

  const top3 = (b0 >>> 1) & 0x07;
  const mid15 = (b1 << 7) | (b2 >>> 1);
  const low15 = (b3 << 7) | (b4 >>> 1);
  return top3 * 2 ** 30 + mid15 * 2 ** 15 + low15;
};

const parseMpeg2PackHeader = (
  bytes: Uint8Array,
  baseOffset: number,
  pushIssue: (message: string) => void
): { totalSize: number; scrSeconds: number | null; muxRate: number | null; stuffingLength: number | null } => {
  if (baseOffset + 14 > bytes.length) {
    return { totalSize: 0, scrSeconds: null, muxRate: null, stuffingLength: null };
  }
  const b4 = bytes[baseOffset + 4] ?? 0;
  const b5 = bytes[baseOffset + 5] ?? 0;
  const b6 = bytes[baseOffset + 6] ?? 0;
  const b7 = bytes[baseOffset + 7] ?? 0;
  const b8 = bytes[baseOffset + 8] ?? 0;
  const b9 = bytes[baseOffset + 9] ?? 0;
  const b10 = bytes[baseOffset + 10] ?? 0;
  const b11 = bytes[baseOffset + 11] ?? 0;
  const b12 = bytes[baseOffset + 12] ?? 0;
  const b13 = bytes[baseOffset + 13] ?? 0;

  const markerOk =
    (b4 & 0x04) !== 0 &&
    (b6 & 0x04) !== 0 &&
    (b8 & 0x04) !== 0 &&
    (b9 & 0x01) !== 0 &&
    (b12 & 0x03) === 0x03 &&
    (b13 & 0xf8) === 0xf8;

  if (!markerOk) {
    pushIssue(`Pack header marker bits look invalid at ${formatOffsetHex(baseOffset)}.`);
  }

  const scrPart1 = ((b4 & 0x03) << 13) | (b5 << 5) | ((b6 & 0xf8) >>> 3);
  const scrPart2 = ((b6 & 0x03) << 13) | (b7 << 5) | ((b8 & 0xf8) >>> 3);
  const scrBase = scrPart1 * 2 ** 15 + scrPart2;
  const scrExt = ((b8 & 0x03) << 7) | ((b9 & 0xfe) >>> 1);
  const scr27MHz = scrBase * 300 + scrExt;
  const scrSeconds = scr27MHz / 27000000;

  const muxRate = (b10 << 14) | (b11 << 6) | ((b12 & 0xfc) >>> 2);
  const stuffingLength = b13 & 0x07;
  const totalSize = 14 + stuffingLength;
  return { totalSize, scrSeconds, muxRate, stuffingLength };
};

const parseSystemHeader = (payload: Uint8Array, pushIssue: (message: string) => void): MpegPsSystemHeaderDetail => {
  const headerLength = payload.length;
  if (payload.length < 6) {
    pushIssue("System header payload is too small to read fixed fields.");
    return {
      headerLength,
      rateBound: null,
      audioBound: null,
      videoBound: null,
      fixedFlag: null,
      cspsFlag: null,
      systemAudioLockFlag: null,
      systemVideoLockFlag: null,
      packetRateRestrictionFlag: null,
      streamBounds: []
    };
  }

  const p0 = payload[0] ?? 0;
  const p1 = payload[1] ?? 0;
  const p2 = payload[2] ?? 0;
  const p3 = payload[3] ?? 0;
  const p4 = payload[4] ?? 0;
  const p5 = payload[5] ?? 0;

  const markerOk = (p0 & 0x80) !== 0 && (p2 & 0x01) !== 0 && (p4 & 0x20) !== 0 && (p5 & 0x7f) === 0x7f;
  if (!markerOk) pushIssue("System header marker bits or reserved bits look unusual.");

  const rateBound = ((p0 & 0x7f) << 15) | (p1 << 7) | ((p2 & 0xfe) >>> 1);
  const audioBound = (p3 & 0xfc) >>> 2;
  const fixedFlag = (p3 & 0x02) !== 0;
  const cspsFlag = (p3 & 0x01) !== 0;
  const systemAudioLockFlag = (p4 & 0x80) !== 0;
  const systemVideoLockFlag = (p4 & 0x40) !== 0;
  const videoBound = p4 & 0x1f;
  const packetRateRestrictionFlag = (p5 & 0x80) !== 0;

  const streamBounds: Array<{
    streamId: number;
    scale: number | null;
    sizeBound: number | null;
    bufferSizeBytes: number | null;
  }> = [];
  const remainder = payload.length - 6;
  if (remainder % 3 !== 0) {
    pushIssue(`System header stream bounds length is not a multiple of 3 bytes (${remainder}).`);
  }
  for (let offset = 6; offset + 3 <= payload.length; offset += 3) {
    const streamId = payload[offset] ?? 0;
    const b1 = payload[offset + 1] ?? 0;
    const b2 = payload[offset + 2] ?? 0;
    if ((b1 & 0xc0) !== 0xc0) {
      streamBounds.push({ streamId, scale: null, sizeBound: null, bufferSizeBytes: null });
      continue;
    }
    const scale = (b1 & 0x20) !== 0 ? 1 : 0;
    const sizeBound = ((b1 & 0x1f) << 8) | b2;
    const bufferSizeBytes = sizeBound * (scale ? 1024 : 128);
    streamBounds.push({ streamId, scale, sizeBound, bufferSizeBytes });
  }

  return {
    headerLength,
    rateBound,
    audioBound,
    videoBound,
    fixedFlag,
    cspsFlag,
    systemAudioLockFlag,
    systemVideoLockFlag,
    packetRateRestrictionFlag,
    streamBounds
  };
};

const parseProgramStreamMap = (
  payload: Uint8Array,
  pushIssue: (message: string) => void
): MpegPsProgramStreamMapDetail => {
  const length = payload.length;
  if (payload.length < 10) {
    pushIssue("Program Stream Map is too small to parse.");
    return {
      length,
      currentNextIndicator: null,
      version: null,
      programStreamInfoLength: null,
      elementaryStreamMapLength: null,
      entries: [],
      crc32: null
    };
  }

  const first = payload[0] ?? 0;
  const second = payload[1] ?? 0;
  const currentNextIndicator = (first & 0x80) !== 0;
  const version = first & 0x1f;
  const markerOk = (second & 0x01) !== 0;
  if (!markerOk) pushIssue("Program Stream Map marker bit is not set.");

  let cursor = 2;
  const programStreamInfoLength = readUint16be(payload, cursor);
  cursor += 2;
  cursor += programStreamInfoLength;
  if (cursor + 2 > payload.length) {
    pushIssue("Program Stream Map ended while skipping program_stream_info.");
    return {
      length,
      currentNextIndicator,
      version,
      programStreamInfoLength,
      elementaryStreamMapLength: null,
      entries: [],
      crc32: null
    };
  }
  const elementaryStreamMapLength = readUint16be(payload, cursor);
  cursor += 2;
  const entriesEnd = cursor + elementaryStreamMapLength;
  if (entriesEnd > payload.length) {
    pushIssue("Program Stream Map elementary stream map length exceeds payload.");
  }
  const entries: Array<{ streamType: number; elementaryStreamId: number; elementaryStreamInfoLength: number }> = [];
  while (cursor + 4 <= payload.length && cursor + 4 <= entriesEnd) {
    const streamType = payload[cursor] ?? 0;
    const elementaryStreamId = payload[cursor + 1] ?? 0;
    const infoLength = readUint16be(payload, cursor + 2);
    cursor += 4;
    cursor += infoLength;
    entries.push({
      streamType,
      elementaryStreamId,
      elementaryStreamInfoLength: infoLength
    });
  }

  const crcOffset = payload.length - 4;
  const crc32 =
    crcOffset >= 0 && crcOffset + 4 <= payload.length
      ? (((payload[crcOffset] ?? 0) << 24) |
          ((payload[crcOffset + 1] ?? 0) << 16) |
          ((payload[crcOffset + 2] ?? 0) << 8) |
          (payload[crcOffset + 3] ?? 0)) >>> 0
      : null;

  return {
    length,
    currentNextIndicator,
    version,
    programStreamInfoLength,
    elementaryStreamMapLength,
    entries,
    crc32
  };
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

  const packHeaders = {
    totalCount: 0,
    mpeg1Count: 0,
    mpeg2Count: 0,
    invalidCount: 0,
    stuffingBytesTotal: 0,
    scr: {
      count: 0,
      firstSeconds: null as number | null,
      lastSeconds: null as number | null,
      minSeconds: null as number | null,
      maxSeconds: null as number | null,
      backwardsCount: 0
    },
    muxRate: { min: null as number | null, max: null as number | null }
  };

  const systemHeaders = {
    totalCount: 0,
    truncatedCount: 0,
    lengthTotal: 0,
    lengthMin: null as number | null,
    lengthMax: null as number | null,
    firstHeader: null as MpegPsSystemHeaderDetail | null
  };

  const programStreamMaps = {
    totalCount: 0,
    truncatedCount: 0,
    firstMap: null as MpegPsProgramStreamMapDetail | null,
    streamTypes: [] as Array<{ streamType: number; count: number }>
  };
  const programStreamMapTypeCounts = new Map<number, number>();

  const streamStats = new Map<number, MutableStream>();
  const getStream = (streamId: number): MutableStream => {
    const existing = streamStats.get(streamId);
    if (existing) return existing;
    const created: MutableStream = {
      streamId,
      kind: classifyStreamId(streamId),
      packetCount: 0,
      packetLengthZeroCount: 0,
      declaredBytesTotal: 0,
      pts: createEmptyPts(),
      dtsCount: 0
    };
    streamStats.set(streamId, created);
    return created;
  };

  const pes = {
    totalPackets: 0,
    totalDeclaredBytes: 0,
    streams: [] as Array<unknown>
  };

  let programEndCodeOffset: number | null = null;

  let chunkBase = -1;
  let chunkBytes = new Uint8Array(0);
  const loadChunk = async (offset: number, requiredBytes: number): Promise<void> => {
    const base = Math.floor(offset / CHUNK_SIZE) * CHUNK_SIZE;
    const localRequired = (offset - base) + requiredBytes;
    const targetSize = Math.max(CHUNK_SIZE + CHUNK_OVERLAP, localRequired);
    const end = Math.min(file.size, base + targetSize);
    chunkBytes = new Uint8Array(await file.slice(base, end).arrayBuffer());
    chunkBase = base;
  };
  const ensureBytes = async (offset: number, requiredBytes: number): Promise<boolean> => {
    if (offset < 0 || requiredBytes < 0) return false;
    if (offset + requiredBytes > file.size) return false;
    if (chunkBase >= 0) {
      const local = offset - chunkBase;
      if (local >= 0 && local + requiredBytes <= chunkBytes.length) return true;
    }
    await loadChunk(offset, requiredBytes);
    const local = offset - chunkBase;
    return local >= 0 && local + requiredBytes <= chunkBytes.length;
  };

  const findNextStartCode = async (offset: number): Promise<number | null> => {
    let cursor = offset;
    while (cursor + 4 <= file.size) {
      const ok = await ensureBytes(cursor, 4);
      if (!ok) return null;
      const local = cursor - chunkBase;
      for (let i = local; i + 4 <= chunkBytes.length; i += 1) {
        if (
          chunkBytes[i] === 0x00 &&
          chunkBytes[i + 1] === 0x00 &&
          chunkBytes[i + 2] === 0x01 &&
          isPacketStartCodeByte(chunkBytes[i + 3] ?? 0)
        ) {
          return chunkBase + i;
        }
      }
      cursor = chunkBase + chunkBytes.length - 3;
    }
    return null;
  };

  let offset = 0;
  let lastScrSeconds: number | null = null;

  while (offset + 4 <= file.size) {
    const ok = await ensureBytes(offset, 4);
    if (!ok) break;
    const local = offset - chunkBase;

    const b0 = chunkBytes[local] ?? 0;
    const b1 = chunkBytes[local + 1] ?? 0;
    const b2 = chunkBytes[local + 2] ?? 0;
    if (b0 !== 0x00 || b1 !== 0x00 || b2 !== 0x01) {
      const next = await findNextStartCode(offset + 1);
      if (next == null) break;
      pushIssue(`Resynced to next start code at ${formatOffsetHex(next)} (from ${formatOffsetHex(offset)}).`);
      offset = next;
      continue;
    }

    const code = chunkBytes[local + 3] ?? 0;
    const startCode = ((b0 << 24) | (b1 << 16) | (b2 << 8) | code) >>> 0;

    if (startCode === PACK_START_CODE) {
      const hdrOk = await ensureBytes(offset, 14);
      if (!hdrOk) {
        pushIssue(`Truncated pack header at ${formatOffsetHex(offset)}.`);
        break;
      }
      const b4 = chunkBytes[local + 4] ?? 0;
      packHeaders.totalCount += 1;

      if ((b4 & 0xc0) === 0x40) {
        packHeaders.mpeg2Count += 1;
        const parsed = parseMpeg2PackHeader(chunkBytes, local, pushIssue);
        if (!parsed.totalSize) {
          pushIssue(`Truncated MPEG-2 pack header at ${formatOffsetHex(offset)}.`);
          break;
        }
        if (parsed.stuffingLength != null) packHeaders.stuffingBytesTotal += parsed.stuffingLength;
        if (typeof parsed.scrSeconds === "number") {
          const scrSeconds = parsed.scrSeconds;
          packHeaders.scr.count += 1;
          packHeaders.scr.firstSeconds = packHeaders.scr.firstSeconds ?? scrSeconds;
          packHeaders.scr.lastSeconds = scrSeconds;
          packHeaders.scr.minSeconds =
            packHeaders.scr.minSeconds == null ? scrSeconds : Math.min(packHeaders.scr.minSeconds, scrSeconds);
          packHeaders.scr.maxSeconds =
            packHeaders.scr.maxSeconds == null ? scrSeconds : Math.max(packHeaders.scr.maxSeconds, scrSeconds);
          if (lastScrSeconds != null && scrSeconds < lastScrSeconds) packHeaders.scr.backwardsCount += 1;
          lastScrSeconds = scrSeconds;
        }
        if (typeof parsed.muxRate === "number") {
          const mux = parsed.muxRate;
          packHeaders.muxRate.min = packHeaders.muxRate.min == null ? mux : Math.min(packHeaders.muxRate.min, mux);
          packHeaders.muxRate.max = packHeaders.muxRate.max == null ? mux : Math.max(packHeaders.muxRate.max, mux);
        }
        if (offset + parsed.totalSize > file.size) {
          pushIssue(`Pack header claims bytes past end of file at ${formatOffsetHex(offset)}.`);
          break;
        }
        offset += parsed.totalSize;
        continue;
      }
      if ((b4 & 0xf0) === 0x20) {
        packHeaders.mpeg1Count += 1;
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
          const value = chunkBytes[offset - chunkBase] ?? 0;
          if (value !== 0xff) break;
          packHeaders.stuffingBytesTotal += 1;
          offset += 1;
        }
        continue;
      }

      packHeaders.invalidCount += 1;
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
      const headerLength = readUint16be(chunkBytes, local + 4);
      const totalSize = 6 + headerLength;
      if (offset + totalSize > file.size) {
        systemHeaders.totalCount += 1;
        systemHeaders.truncatedCount += 1;
        pushIssue(`Truncated system header at ${formatOffsetHex(offset)} (declared length ${headerLength}).`);
        break;
      }
      const okPayload = await ensureBytes(offset, totalSize);
      if (!okPayload) {
        pushIssue(`Unable to read full system header at ${formatOffsetHex(offset)}.`);
        break;
      }
      const payload = chunkBytes.subarray(local + 6, local + 6 + headerLength);
      systemHeaders.totalCount += 1;
      systemHeaders.lengthTotal += headerLength;
      systemHeaders.lengthMin = systemHeaders.lengthMin == null ? headerLength : Math.min(systemHeaders.lengthMin, headerLength);
      systemHeaders.lengthMax = systemHeaders.lengthMax == null ? headerLength : Math.max(systemHeaders.lengthMax, headerLength);
      if (!systemHeaders.firstHeader) {
        systemHeaders.firstHeader = parseSystemHeader(payload, pushIssue);
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
      const mapLength = readUint16be(chunkBytes, local + 4);
      const totalSize = 6 + mapLength;
      if (offset + totalSize > file.size) {
        programStreamMaps.totalCount += 1;
        programStreamMaps.truncatedCount += 1;
        pushIssue(`Truncated Program Stream Map at ${formatOffsetHex(offset)} (declared length ${mapLength}).`);
        break;
      }
      const okPayload = await ensureBytes(offset, totalSize);
      if (!okPayload) {
        pushIssue(`Unable to read full Program Stream Map at ${formatOffsetHex(offset)}.`);
        break;
      }
      const payload = chunkBytes.subarray(local + 6, local + 6 + mapLength);
      const parsed = parseProgramStreamMap(payload, pushIssue);
      programStreamMaps.totalCount += 1;
      if (!programStreamMaps.firstMap) programStreamMaps.firstMap = parsed;
      for (const entry of parsed.entries) {
        programStreamMapTypeCounts.set(entry.streamType, (programStreamMapTypeCounts.get(entry.streamType) || 0) + 1);
      }
      offset += totalSize;
      continue;
    }

    if (startCode === PROGRAM_END_CODE) {
      programEndCodeOffset = programEndCodeOffset ?? offset;
      offset += 4;
      break;
    }

    const okPes = await ensureBytes(offset, 6);
    if (!okPes) {
      pushIssue(`Truncated packet header at ${formatOffsetHex(offset)}.`);
      break;
    }
    const streamId = code;
    const packetLength = readUint16be(chunkBytes, local + 4);
    const stream = getStream(streamId);
    pes.totalPackets += 1;
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
    pes.totalDeclaredBytes += totalSize;

    const headerOk = await ensureBytes(offset, Math.min(totalSize, 64));
    if (headerOk && packetLength >= 3) {
      const flags0 = chunkBytes[local + 6] ?? 0;
      const flags1 = chunkBytes[local + 7] ?? 0;
      const headerDataLength = chunkBytes[local + 8] ?? 0;
      if ((flags0 & 0xc0) === 0x80 && packetLength >= 3 + headerDataLength && totalSize >= 9) {
        const ptsDtsFlags = (flags1 >>> 6) & 0x03;
        const optionalStart = local + 9;
        if ((ptsDtsFlags === 2 || ptsDtsFlags === 3) && headerDataLength >= 5) {
          const pts = decodeTimestamp33(chunkBytes, optionalStart);
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
            const dts = decodeTimestamp33(chunkBytes, optionalStart + 5);
            if (dts != null) stream.dtsCount += 1;
          }
        }
      }
    }

    offset += totalSize;
  }

  const streams = Array.from(streamStats.values())
    .sort((a, b) => a.streamId - b.streamId)
    .map(s => {
      const durationSeconds =
        s.pts.count >= 2 && s.pts.backwardsCount === 0 && s.pts.first != null && s.pts.last != null && s.pts.last >= s.pts.first
          ? (s.pts.last - s.pts.first) / 90000
          : null;
      return {
        streamId: s.streamId,
        kind: s.kind,
        packetCount: s.packetCount,
        packetLengthZeroCount: s.packetLengthZeroCount,
        declaredBytesTotal: s.declaredBytesTotal,
        pts: {
          count: s.pts.count,
          first: s.pts.first,
          last: s.pts.last,
          min: s.pts.min,
          max: s.pts.max,
          backwardsCount: s.pts.backwardsCount,
          durationSeconds: durationSeconds != null ? Math.round(durationSeconds * 1000) / 1000 : null
        },
        dtsCount: s.dtsCount
      };
    });

  programStreamMaps.streamTypes = Array.from(programStreamMapTypeCounts.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([streamType, count]) => ({ streamType, count }));

  return {
    isMpegProgramStream: true,
    fileSize: file.size,
    packHeaders,
    systemHeaders,
    programStreamMaps,
    pes: {
      totalPackets: pes.totalPackets,
      totalDeclaredBytes: pes.totalDeclaredBytes,
      streams
    },
    programEndCodeOffset,
    issues
  };
}
