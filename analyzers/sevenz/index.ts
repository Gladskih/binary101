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
export * from "./types.js";

const SIGNATURE_BYTES = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const START_HEADER_SIZE = 32;

const hasSignature = (dv: DataView | null): boolean => {
  if (!dv || dv.byteLength < SIGNATURE_BYTES.length) return false;
  for (let i = 0; i < SIGNATURE_BYTES.length; i += 1) {
    if (dv.getUint8(i) !== SIGNATURE_BYTES[i]) return false;
  }
  return true;
};

const parseNextHeader = (dv: DataView | null, issues: string[]): SevenZipParsedNextHeader => {
  if (!dv || dv.byteLength === 0) {
    issues.push("Next header is empty.");
    return { kind: "empty" };
  }
  const firstId = dv.getUint8(0);
  const ctx: SevenZipContext = { dv, offset: 1, issues };
  if (firstId === 0x01) {
    const sections = parseHeader(ctx);
    return { kind: "header", sections };
  }
  if (firstId === 0x17) {
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
  const startHeaderBuffer = await file.slice(0, START_HEADER_SIZE).arrayBuffer();
  const startHeader = new DataView(startHeaderBuffer);
  if (startHeader.byteLength < START_HEADER_SIZE || !hasSignature(startHeader)) {
    return { is7z: false, issues };
  }
  const versionMajor = startHeader.getUint8(6);
  const versionMinor = startHeader.getUint8(7);
  const startHeaderCrc = startHeader.getUint32(8, true);
  const nextHeaderOffset = startHeader.getBigUint64(12, true);
  const nextHeaderSize = startHeader.getBigUint64(20, true);
  const nextHeaderCrc = startHeader.getUint32(28, true);
  const absoluteNextHeaderOffset = 32n + nextHeaderOffset;
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
  } else {
    const structure = deriveStructure(parsedNextHeader, issues);
    if (structure) result.structure = structure;
  }
  return result;
}

export const isSevenZip = async (file: File): Promise<boolean> => {
  const dv = new DataView(await file.slice(0, START_HEADER_SIZE).arrayBuffer());
  return hasSignature(dv);
};

export const hasSevenZipSignature = (dv: DataView): boolean => hasSignature(dv);
