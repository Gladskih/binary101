"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import type { SevenZipFileSummary, SevenZipFolderSummary } from "../analyzers/sevenz/index.js";
import { decompressLzmaWithProperties } from "../analyzers/sevenz/lzma.js";
import { toSafeNumber } from "../analyzers/sevenz/readers.js";

type SevenZipDeps = {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
};

const DECIMAL_RADIX = 10;

const sanitizeDownloadName = (entry: SevenZipFileSummary): string => {
  const parts = entry.name.split(/[\\/]/);
  const last = parts[parts.length - 1] || "entry.bin";
  return last.trim().length ? last.trim() : "entry.bin";
};

const findSevenZipEntry = (
  parseResult: ParseForUiResult,
  index: number
): SevenZipFileSummary | null => {
  if (parseResult.analyzer !== "sevenZip") return null;
  return parseResult.parsed.structure?.files.find(file => file.index === index) || null;
};

const getFolder = (
  parseResult: ParseForUiResult,
  entry: SevenZipFileSummary
): SevenZipFolderSummary | null => {
  if (parseResult.analyzer !== "sevenZip" || entry.folderIndex == null) return null;
  return parseResult.parsed.structure?.folders[entry.folderIndex] || null;
};

const sumPreviousSubstreams = (
  folder: SevenZipFolderSummary,
  streamIndex: number
): bigint | null => {
  let offset = 0n;
  for (let index = 0; index < streamIndex; index += 1) {
    const size = folder.substreams[index]?.size;
    if (size == null) return null;
    offset += size;
  }
  return offset;
};

const sliceDecodedEntry = (
  decoded: Uint8Array,
  folder: SevenZipFolderSummary,
  entry: SevenZipFileSummary
): Uint8Array => {
  const start = sumPreviousSubstreams(folder, entry.folderStreamIndex ?? 0);
  const length = typeof entry.uncompressedSize === "bigint" ? entry.uncompressedSize : null;
  const startNumber = toSafeNumber(start);
  const lengthNumber = toSafeNumber(length);
  if (startNumber == null || lengthNumber == null) {
    throw new Error("7z entry decoded range exceeds supported size.");
  }
  if (startNumber + lengthNumber > decoded.byteLength) {
    throw new Error("7z entry decoded range exceeds folder data.");
  }
  return decoded.slice(startNumber, startNumber + lengthNumber);
};

const extractEntry = async (
  archive: File,
  folder: SevenZipFolderSummary,
  entry: SevenZipFileSummary
): Promise<Blob> => {
  const offset = toSafeNumber(folder.packedOffset);
  const packedSize = toSafeNumber(folder.packedSize);
  const unpackSize = typeof folder.unpackSize === "bigint" ? folder.unpackSize : null;
  const propertyBytes = folder.coders[0]?.propertyBytes || [];
  if (offset == null || packedSize == null || unpackSize == null) {
    throw new Error("7z folder bounds are not available.");
  }
  if (offset + packedSize > archive.size) throw new Error("7z folder extends beyond file bounds.");
  const packedBytes = new Uint8Array(await archive.slice(offset, offset + packedSize).arrayBuffer());
  const entryBytes = sliceDecodedEntry(
    await decompressLzmaWithProperties(propertyBytes, packedBytes, unpackSize),
    folder,
    entry
  );
  const buffer = new ArrayBuffer(entryBytes.byteLength);
  new Uint8Array(buffer).set(entryBytes);
  return new Blob([buffer]);
};

const triggerDownload = (blob: Blob, suggestedName: string): void => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = suggestedName;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

const createSevenZipEntryClickHandler = ({ getParseResult, getFile, setStatusMessage }: SevenZipDeps) =>
  async (event: Event): Promise<void> => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const button = target.closest("button.sevenZipExtractButton");
    if (!(button instanceof HTMLButtonElement)) return;
    const entryIndex = Number.parseInt(button.getAttribute("data-sevenzip-entry") || "", DECIMAL_RADIX);
    if (Number.isNaN(entryIndex)) return;
    const parseResult = getParseResult();
    const entry = findSevenZipEntry(parseResult, entryIndex);
    if (!entry) {
      setStatusMessage("7z entry not found.");
      return;
    }
    if (entry.extractError) {
      setStatusMessage(entry.extractError);
      return;
    }
    const folder = getFolder(parseResult, entry);
    const file = getFile();
    if (!folder || !file) {
      setStatusMessage(!file ? "No file selected." : "7z folder not found.");
      return;
    }
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Decompressing...";
    try {
      triggerDownload(await extractEntry(file, folder, entry), sanitizeDownloadName(entry));
      setStatusMessage(null);
    } catch (error) {
      const message = error instanceof Error && error.message ? error.message : String(error);
      setStatusMessage(`Extract failed: ${message}`);
    } finally {
      button.disabled = false;
      button.textContent = originalText || "Extract";
    }
  };

export { createSevenZipEntryClickHandler };
