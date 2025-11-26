"use strict";

import { CODER_ARCH_HINTS, describeCoderId, normalizeMethodId } from "./coders.js";
import { toSafeNumber } from "./readers.js";
import type {
  SevenZipCoder,
  SevenZipFolderCoderRecord,
  SevenZipFolderSummary,
  SevenZipHeaderSections,
  SevenZipStructure,
  SevenZipFileSummary
} from "./types.js";

const sumBigIntArray = (values: Array<bigint | number | null | undefined>): bigint =>
  values.reduce<bigint>(
    (total: bigint, value: bigint | number | null | undefined) =>
      total + (typeof value === "bigint" ? value : 0n),
    0n
  );

export const buildFolderDetails = (
  sections: SevenZipHeaderSections,
  issues: string[]
): { folders: SevenZipFolderSummary[] } => {
  const mainStreams = sections.mainStreamsInfo;
  const unpackInfo = mainStreams?.unpackInfo;
  const packInfo = mainStreams?.packInfo;
  if (!unpackInfo?.folders?.length) return { folders: [] };
  const folderCount = unpackInfo.folders.length;
  const numUnpackStreams =
    mainStreams?.subStreamsInfo?.numUnpackStreams || new Array(folderCount).fill(1);
  const substreamSizes = mainStreams?.subStreamsInfo?.substreamSizes || [];
  const substreamCrcs = mainStreams?.subStreamsInfo?.substreamCrcs;
  const crcDefined = substreamCrcs?.definedFlags || [];
  const crcMap = new Map((substreamCrcs?.digests || []).map(digest => [digest.index, digest.crc]));
  const packSizes = packInfo?.packSizes || [];
  const folders: SevenZipFolderSummary[] = [];
  let packCursor = 0;
  let substreamSizeCursor = 0;
  let crcCursor = 0;
  for (let i = 0; i < folderCount; i += 1) {
    const folder = unpackInfo.folders[i];
    if (!folder) {
      issues.push("Folder entry is missing from UnpackInfo.");
      break;
    }
    const unpackStreams = toSafeNumber(numUnpackStreams[i]) ?? 1;
    const unpackSizes = unpackInfo.unpackSizes?.[i] || [];
    const unpackSize = unpackSizes.length ? sumBigIntArray(unpackSizes) : null;
    const packedStreams = Math.max(folder.numPackedStreams || 0, 0);
    const packedSizes: Array<bigint | null> = [];
    for (let j = 0; j < packedStreams; j += 1) {
      if (packCursor >= packSizes.length) break;
      const packSizeEntry = packSizes[packCursor];
      packedSizes.push(packSizeEntry ?? null);
      packCursor += 1;
    }
    const packedSize = packedSizes.length ? sumBigIntArray(packedSizes) : null;
    const substreams: SevenZipFolderSummary["substreams"] = [];
    let consumed = 0n;
    for (let s = 0; s < unpackStreams; s += 1) {
      let size = null;
      if (unpackStreams === 1) {
        size = unpackSize ?? unpackSizes[0] ?? null;
      } else if (s < unpackStreams - 1) {
        size = substreamSizes[substreamSizeCursor] ?? null;
        substreamSizeCursor += 1;
      } else if (typeof unpackSize === "bigint") {
        size = unpackSize - consumed;
      }
      if (typeof size === "number") size = BigInt(size);
      if (typeof size === "bigint") consumed += size;
      const crcFlag = crcDefined[crcCursor];
      let crc: number | null = null;
      if (crcFlag) {
        const value = crcMap.get(crcCursor);
        crc = typeof value === "number" ? value : null;
      }
      crcCursor += 1;
      substreams.push({ size: size as bigint | null, crc });
    }
    const folderUnpackSize =
      substreams.some(sub => typeof sub.size === "bigint")
        ? sumBigIntArray(substreams.map(sub => sub.size || 0n))
        : unpackSize;
    const coders: SevenZipCoder[] = (folder.coders || []).map(
      (coder: SevenZipFolderCoderRecord): SevenZipCoder => {
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
      }
    );
    const isEncrypted = coders.some(coder => coder.isEncryption);
    const folderSummary: SevenZipFolderSummary = {
      index: i,
      unpackSize: folderUnpackSize,
      packedSize,
      coders,
      numUnpackStreams: unpackStreams,
      substreams,
      isEncrypted
    };
    folders.push(folderSummary);
  }
  if (substreamSizeCursor < substreamSizes.length) {
    issues.push("Extra substream size entries were not matched to folders.");
  }
  return { folders };
};

export const buildFileDetails = (
  sections: SevenZipHeaderSections,
  folders: SevenZipFolderSummary[],
  issues: string[]
): { files: SevenZipFileSummary[] } => {
  const sourceFiles = sections.filesInfo?.files;
  if (!sourceFiles?.length) return { files: [] };
  const files: SevenZipFileSummary[] = sourceFiles.map(file => ({
    index: file.index,
    name: file.name || "(no name)",
    folderIndex: null,
    uncompressedSize: null,
    packedSize: null,
    compressionRatio: null,
    crc32: null,
    modifiedTime: file.modifiedTime ?? null,
    attributes: file.attributes ?? null,
    hasStream: file.hasStream ?? true,
    isEmptyStream: file.isEmptyStream ?? false,
    isEmptyFile: file.isEmptyFile ?? false,
    isDirectory: file.isDirectory ?? false,
    isAnti: file.isAnti ?? false,
    isEncrypted: false
  }));
  const filesWithStreams = files.filter(file => file.hasStream !== false);
  let fileStreamIndex = 0;
  folders.forEach(folder => {
    folder.substreams.forEach(sub => {
      const file = filesWithStreams[fileStreamIndex];
      if (!file) return;
      file.folderIndex = folder.index;
      file.uncompressedSize = sub.size ?? folder.unpackSize ?? null;
      const packedSize = folder.numUnpackStreams === 1 ? folder.packedSize : null;
      file.packedSize = packedSize;
      const uncompNum =
        typeof file.uncompressedSize === "bigint"
          ? toSafeNumber(file.uncompressedSize)
          : file.uncompressedSize;
      const packedNum = typeof packedSize === "bigint" ? toSafeNumber(packedSize) : packedSize;
      const ratio =
        packedNum != null && uncompNum != null && uncompNum > 0
          ? (packedNum / uncompNum) * 100
          : null;
      file.compressionRatio = Number.isFinite(ratio) ? ratio : null;
      file.crc32 = sub.crc ?? null;
      file.isEncrypted = folder.isEncrypted;
      file.isDirectory = Boolean(file.isDirectory);
      file.isEmpty =
        (uncompNum === 0 || file.uncompressedSize === 0n) && file.isDirectory !== true;
      fileStreamIndex += 1;
    });
  });
  if (fileStreamIndex < filesWithStreams.length) {
    issues.push("Some file streams were not matched to folders.");
  }
  files.forEach(file => {
    if (file.folderIndex == null) file.folderIndex = null;
    if (file.uncompressedSize == null) file.uncompressedSize = null;
    if (file.packedSize == null) file.packedSize = null;
    if (file.compressionRatio == null) file.compressionRatio = null;
    if (file.crc32 == null) file.crc32 = null;
    if (file.isEncrypted == null) file.isEncrypted = false;
    if (file.isEmpty == null) {
      const uncompNum =
        typeof file.uncompressedSize === "bigint"
          ? toSafeNumber(file.uncompressedSize)
          : file.uncompressedSize;
      file.isEmpty = (uncompNum === 0 || file.uncompressedSize === 0n) && !file.isDirectory;
    }
  });
  return { files };
};

export const deriveStructure = (
  parsed: { kind: string; sections?: SevenZipHeaderSections },
  issues: string[]
): SevenZipStructure | null => {
  if (parsed.kind !== "header" || !parsed.sections) return null;
  const sections = parsed.sections;
  const folderDetails = buildFolderDetails(sections, issues);
  const fileDetails = buildFileDetails(sections, folderDetails.folders, issues);
  const filesWithStreams = fileDetails.files.filter(file => file.hasStream !== false);
  const archiveFlags = {
    isSolid:
      folderDetails.folders.some(folder => folder.numUnpackStreams > 1) ||
      filesWithStreams.length > folderDetails.folders.length,
    isHeaderEncrypted: false,
    hasEncryptedContent: folderDetails.folders.some(folder => folder.isEncrypted)
  };
  return {
    archiveFlags,
    folders: folderDetails.folders,
    files: fileDetails.files
  };
};
