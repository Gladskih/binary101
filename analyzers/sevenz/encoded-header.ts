"use strict";

import type {
  SevenZipFolderParseResult,
  SevenZipParsedNextHeader
} from "./types.js";
import { parseHeader } from "./header-sections.js";
import { toSafeNumber } from "./readers.js";
import { decodeLzmaCoder, isLzmaMethod } from "./lzma-coder.js";
import { SEVENZIP_HEADER_MARKER, SEVENZIP_SIGNATURE_HEADER_SIZE } from "./layout.js";
import { crc32 } from "../crc32.js";

const SINGLE_STREAM_COUNT = 1;

const getSingleLzmaFolder = (
  parsed: Extract<SevenZipParsedNextHeader, { kind: "encoded" }>
): SevenZipFolderParseResult | null => {
  const folders = parsed.headerStreams.unpackInfo?.folders || [];
  if (folders.length !== SINGLE_STREAM_COUNT) return null;
  const folder = folders[0];
  if (!folder || folder.coders.length !== SINGLE_STREAM_COUNT) return null;
  if (folder.numPackedStreams !== 1 || folder.numBindPairs !== 0) return null;
  const coder = folder.coders[0];
  return coder?.inStreams === 1 && coder.outStreams === 1 && isLzmaMethod(coder.methodId)
    ? folder : null;
};

const getSingleValue = <T>(values: T[] | undefined): T | null =>
  values?.length === SINGLE_STREAM_COUNT && values[0] != null ? values[0] : null;

const readPackedHeader = async (
  file: File, packPos: bigint, packSize: bigint
): Promise<Uint8Array> => {
  const packedOffset = SEVENZIP_SIGNATURE_HEADER_SIZE + packPos;
  const offset = toSafeNumber(packedOffset);
  const size = toSafeNumber(packSize);
  if (offset == null || size == null) {
    throw new Error("Encoded 7z header packed stream exceeds supported range.");
  }
  if (packPos < 0n || packSize < 0n || packedOffset + packSize > BigInt(file.size)) {
    throw new Error("Encoded 7z header packed stream lies outside the file bounds.");
  }
  return new Uint8Array(await file.slice(offset, offset + size).arrayBuffer());
};

const checkHeaderCrc = (bytes: Uint8Array, expected: number | undefined, label: string): void => {
  if (expected !== undefined && crc32(bytes) !== expected) throw new Error(`${label} CRC mismatch.`);
};

const parseDecodedHeader = (
  decoded: Uint8Array, issues: string[]
): SevenZipParsedNextHeader | null => {
  if (decoded[0] !== SEVENZIP_HEADER_MARKER) {
    issues.push("Decoded 7z header did not start with a Header marker.");
    return null;
  }
  return { kind: "header", sections: parseHeader({
    dv: new DataView(decoded.buffer, decoded.byteOffset, decoded.byteLength), offset: 1, issues
  }) };
};

export const decodeEncodedHeader = async (
  file: File,
  parsed: Extract<SevenZipParsedNextHeader, { kind: "encoded" }>,
  issues: string[]
): Promise<SevenZipParsedNextHeader | null> => {
  if (parsed.hasEncryptedHeader) {
    issues.push("Encoded 7z header is encrypted; unable to decode.");
    return null;
  }
  const folder = getSingleLzmaFolder(parsed);
  const coder = folder?.coders[0] || null;
  const packInfo = parsed.headerStreams.packInfo;
  const packPos = packInfo?.packPos;
  const packSize = getSingleValue(packInfo?.packSizes);
  const unpackSize = getSingleValue(parsed.headerStreams.unpackInfo?.unpackSizes?.[0]);
  if (!folder || !coder || packPos == null || packSize == null || unpackSize == null) {
    issues.push("Encoded 7z header uses an unsupported stream layout.");
    return null;
  }
  try {
    const packed = await readPackedHeader(file, packPos, packSize);
    checkHeaderCrc(packed, packInfo?.packCrcs.find(digest => digest.index === 0)?.crc,
      "Encoded 7z packed header");
    const decoded = await decodeLzmaCoder(coder.methodId, coder.propertyBytes || [], packed, unpackSize);
    checkHeaderCrc(decoded,
      parsed.headerStreams.unpackInfo?.folderCrcs?.digests.find(digest => digest.index === 0)?.crc,
      "Decoded 7z header");
    return parseDecodedHeader(decoded, issues);
  } catch (error) {
    const message = error instanceof Error && error.message ? error.message : String(error);
    issues.push(message.startsWith("Encoded 7z header packed stream")
      ? message : `Encoded 7z header decode failed: ${message}`);
    return null;
  }
};
