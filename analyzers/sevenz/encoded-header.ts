"use strict";

import type {
  SevenZipFolderParseResult,
  SevenZipParsedNextHeader
} from "./types.js";
import { parseHeader } from "./header-sections.js";
import { toSafeNumber } from "./readers.js";
import { decompressLzmaWithProperties } from "./lzma.js";
import { SEVENZIP_HEADER_MARKER, SEVENZIP_SIGNATURE_HEADER_SIZE } from "./layout.js";
import { SEVENZIP_LZMA_METHOD_ID } from "./method-ids.js";

const SINGLE_STREAM_COUNT = 1;

const getSingleLzmaFolder = (
  parsed: Extract<SevenZipParsedNextHeader, { kind: "encoded" }>
): SevenZipFolderParseResult | null => {
  const folders = parsed.headerStreams.unpackInfo?.folders || [];
  if (folders.length !== SINGLE_STREAM_COUNT) return null;
  const folder = folders[0];
  if (!folder || folder.coders.length !== SINGLE_STREAM_COUNT) return null;
  const coder = folder.coders[0];
  return coder?.methodId === SEVENZIP_LZMA_METHOD_ID ? folder : null;
};

const getSingleValue = <T>(values: T[] | undefined): T | null =>
  values?.length === SINGLE_STREAM_COUNT && values[0] != null ? values[0] : null;

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
  const packedOffset = SEVENZIP_SIGNATURE_HEADER_SIZE + packPos;
  const offsetNumber = toSafeNumber(packedOffset);
  const sizeNumber = toSafeNumber(packSize);
  if (offsetNumber == null || sizeNumber == null) {
    issues.push("Encoded 7z header packed stream exceeds supported range.");
    return null;
  }
  if (packedOffset + packSize > BigInt(file.size || 0)) {
    issues.push("Encoded 7z header packed stream lies outside the file bounds.");
    return null;
  }
  const propertyBytes = coder.propertyBytes || [];
  const packedBytes = new Uint8Array(
    await file.slice(offsetNumber, offsetNumber + sizeNumber).arrayBuffer()
  );
  try {
    const decoded = await decompressLzmaWithProperties(propertyBytes, packedBytes, unpackSize);
    const ctx = {
      dv: new DataView(decoded.buffer, decoded.byteOffset, decoded.byteLength),
      offset: Uint8Array.BYTES_PER_ELEMENT,
      issues
    };
    if (decoded[0] !== SEVENZIP_HEADER_MARKER) {
      issues.push("Decoded 7z header did not start with a Header marker.");
      return null;
    }
    return { kind: "header", sections: parseHeader(ctx) };
  } catch (error) {
    const message = error instanceof Error && error.message ? error.message : String(error);
    issues.push(`Encoded 7z header decode failed: ${message}`);
    return null;
  }
};
