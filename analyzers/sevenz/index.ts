"use strict";

import {
  type SevenZipCoder,
  type SevenZipFolderParseResult,
  type SevenZipHeaderFolder,
  type SevenZipParsedNextHeader,
  type SevenZipParseResult,
  type SevenZipContext
} from "./types.js";
import { CODER_ARCH_HINTS, describeCoderId, normalizeMethodId } from "./coders.js";
import { parseHeader } from "./header-sections.js";
import { parseStreamsInfo } from "./streams-info.js";
import { toSafeNumber } from "./readers.js";
import { deriveStructure } from "./structure.js";
import { decodeEncodedHeader } from "./encoded-header.js";
import {
  SEVENZIP_ARCHIVE_VERSION_MAJOR_OFFSET,
  SEVENZIP_ARCHIVE_VERSION_MINOR_OFFSET,
  SEVENZIP_ENCODED_HEADER_MARKER,
  SEVENZIP_HEADER_MARKER,
  SEVENZIP_NEXT_HEADER_CRC_OFFSET,
  SEVENZIP_NEXT_HEADER_OFFSET_OFFSET,
  SEVENZIP_NEXT_HEADER_SIZE_OFFSET,
  SEVENZIP_SIGNATURE_BYTES,
  SEVENZIP_SIGNATURE_HEADER_SIZE,
  SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER,
  SEVENZIP_START_HEADER_CRC_OFFSET
} from "./layout.js";
export * from "./types.js";

const FIRST_HEADER_BYTE_OFFSET = 0;

const hasSignature = (dv: DataView | null): boolean => {
  if (!dv || dv.byteLength < SEVENZIP_SIGNATURE_BYTES.length) return false;
  for (let i = 0; i < SEVENZIP_SIGNATURE_BYTES.length; i += 1) {
    if (dv.getUint8(i) !== SEVENZIP_SIGNATURE_BYTES[i]) return false;
  }
  return true;
};

const parseNextHeader = (dv: DataView | null, issues: string[]): SevenZipParsedNextHeader => {
  if (!dv || dv.byteLength === 0) {
    issues.push("Next header is empty.");
    return { kind: "empty" };
  }
  const firstId = dv.getUint8(FIRST_HEADER_BYTE_OFFSET);
  const ctx: SevenZipContext = { dv, offset: Uint8Array.BYTES_PER_ELEMENT, issues };
  if (firstId === SEVENZIP_HEADER_MARKER) {
    const sections = parseHeader(ctx);
    return { kind: "header", sections };
  }
  if (firstId === SEVENZIP_ENCODED_HEADER_MARKER) {
    const streams = parseStreamsInfo(ctx);
    const unpackInfo = streams.unpackInfo;
    const folders: SevenZipHeaderFolder[] =
      unpackInfo?.folders?.map((folder: SevenZipFolderParseResult, index: number) => {
        const coders: SevenZipCoder[] = folder.coders.map(coder => {
          const normalized = normalizeMethodId(coder.methodId);
          const id = describeCoderId(normalized);
          const archHint = CODER_ARCH_HINTS[normalized];
          const isEncryption = normalized === "06f10701";
          const coderInfo: SevenZipCoder = {
            id,
            methodId: coder.methodId,
            numInStreams: coder.inStreams,
            numOutStreams: coder.outStreams,
            properties: coder.properties ?? null,
            isEncryption
          };
          if (archHint) coderInfo.archHint = archHint;
          return coderInfo;
        });
        const isEncrypted = coders.some(coder => coder.isEncryption);
        return {
          index,
          coders,
          isEncrypted
        };
      }) || [];
    const hasEncryptedHeader = folders.some(folder => folder.isEncrypted);
    return {
      kind: "encoded",
      headerStreams: streams,
      headerCoders: folders,
      hasEncryptedHeader
    };
  }
  issues.push(`Unexpected next header type 0x${firstId.toString(16)}.`);
  return { kind: "unknown", type: firstId };
};

export async function parseSevenZip(file: File): Promise<SevenZipParseResult> {
  const issues: string[] = [];
  const startHeaderBuffer = await file.slice(0, SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER).arrayBuffer();
  const startHeader = new DataView(startHeaderBuffer);
  if (startHeader.byteLength < SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER || !hasSignature(startHeader)) {
    return { is7z: false, issues };
  }
  const versionMajor = startHeader.getUint8(SEVENZIP_ARCHIVE_VERSION_MAJOR_OFFSET);
  const versionMinor = startHeader.getUint8(SEVENZIP_ARCHIVE_VERSION_MINOR_OFFSET);
  const startHeaderCrc = startHeader.getUint32(SEVENZIP_START_HEADER_CRC_OFFSET, true);
  const nextHeaderOffset = startHeader.getBigUint64(SEVENZIP_NEXT_HEADER_OFFSET_OFFSET, true);
  const nextHeaderSize = startHeader.getBigUint64(SEVENZIP_NEXT_HEADER_SIZE_OFFSET, true);
  const nextHeaderCrc = startHeader.getUint32(SEVENZIP_NEXT_HEADER_CRC_OFFSET, true);
  const absoluteNextHeaderOffset = SEVENZIP_SIGNATURE_HEADER_SIZE + nextHeaderOffset;
  const sizeNumber = toSafeNumber(nextHeaderSize);
  const offsetNumber = toSafeNumber(absoluteNextHeaderOffset);
  const result: SevenZipParseResult = {
    is7z: true,
    startHeader: {
      versionMajor,
      versionMinor,
      startHeaderCrc,
      nextHeaderOffset,
      nextHeaderSize,
      nextHeaderCrc,
      absoluteNextHeaderOffset
    },
    issues
  };
  if (offsetNumber == null || sizeNumber == null) {
    issues.push("Next header offset or size exceeds supported range.");
    return result;
  }
  const fileSize = file.size || 0;
  if (absoluteNextHeaderOffset + nextHeaderSize > BigInt(fileSize)) {
    issues.push("Next header lies outside the file bounds.");
    return result;
  }
  let nextHeaderDv: DataView | null = null;
  if (sizeNumber > 0) {
    const buffer = await file
      .slice(offsetNumber, offsetNumber + sizeNumber)
      .arrayBuffer();
    nextHeaderDv = new DataView(buffer);
  }
  const parsedNextHeader = parseNextHeader(nextHeaderDv, issues);
  result.nextHeader = {
    offset: absoluteNextHeaderOffset,
    size: nextHeaderSize,
    crc: nextHeaderCrc,
    parsed: parsedNextHeader
  };
  if (parsedNextHeader.kind === "header") {
    const sections = parsedNextHeader.sections;
    if (sections.filesInfo?.fileCount === 0) {
      issues.push("No file entries were found in the archive header.");
    }
    const structure = deriveStructure(parsedNextHeader, issues);
    if (structure) {
      result.structure = structure;
      if (sections.filesInfo) {
        sections.filesInfo.files = structure.files;
      }
    }
  } else if (parsedNextHeader.kind === "encoded") {
    result.headerEncoding = {
      coders: parsedNextHeader.headerCoders,
      hasEncryptedHeader: parsedNextHeader.hasEncryptedHeader
    };
    const decodedHeader = await decodeEncodedHeader(file, parsedNextHeader, issues);
    if (decodedHeader) {
      result.decodedHeader = decodedHeader;
      const structure = deriveStructure(decodedHeader, issues);
      if (structure) result.structure = structure;
    }
  } else {
    const structure = deriveStructure(parsedNextHeader, issues);
    if (structure) result.structure = structure;
  }
  return result;
}

export const isSevenZip = async (file: File): Promise<boolean> => {
  const dv = new DataView(await file.slice(0, SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER).arrayBuffer());
  return hasSignature(dv);
};

export const hasSevenZipSignature = (dv: DataView): boolean => hasSignature(dv);
