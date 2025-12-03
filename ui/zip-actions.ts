"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import type { ZipCentralDirectoryEntry } from "../analyzers/zip/index.js";

type ZipDeps = {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
};

const sanitizeDownloadName = (entry: ZipCentralDirectoryEntry): string => {
  const name = typeof entry.fileName === "string" && entry.fileName.length ? entry.fileName : "entry.bin";
  const parts = name.split(/[\\/]/);
  const last = parts[parts.length - 1] || "entry.bin";
  return last.trim().length ? last.trim() : "entry.bin";
};

const findZipEntryByIndex = (
  parseResult: ParseForUiResult,
  index: number
): ZipCentralDirectoryEntry | null => {
  if (parseResult.analyzer !== "zip") return null;
  const entries = parseResult.parsed.centralDirectory?.entries;
  if (!Array.isArray(entries)) return null;
  return entries.find(entry => entry.index === index) || null;
};

const sliceZipEntryBlob = (file: File, entry: ZipCentralDirectoryEntry): Blob => {
  if (entry.dataOffset == null || entry.dataLength == null) {
    throw new Error("Entry is missing data bounds.");
  }
  return file.slice(entry.dataOffset, entry.dataOffset + entry.dataLength);
};

const decompressZipEntry = async (
  entry: ZipCentralDirectoryEntry,
  compressedBlob: Blob
): Promise<Blob> => {
  if (entry.compressionMethod === 0) return compressedBlob;
  if (typeof DecompressionStream !== "function") {
    throw new Error("Browser does not support DecompressionStream for deflated entries.");
  }
  const stream = compressedBlob.stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Response(stream).blob();
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

const createZipEntryClickHandler = ({ getParseResult, getFile, setStatusMessage }: ZipDeps) =>
  async (event: Event): Promise<void> => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const buttonTarget: HTMLButtonElement | null =
      target instanceof HTMLButtonElement ? target : null;
    const indexAttr = target.getAttribute("data-zip-entry");
    if (!indexAttr) return;
    const entryIndex = Number.parseInt(indexAttr, 10);
    if (Number.isNaN(entryIndex)) return;
    const entry = findZipEntryByIndex(getParseResult(), entryIndex);
    if (!entry) {
      setStatusMessage("ZIP entry not found.");
      return;
    }
    if (entry.extractError) {
      setStatusMessage(entry.extractError);
      return;
    }
    const file = getFile();
    if (!file) {
      setStatusMessage("No file selected.");
      return;
    }
    if (entry.compressionMethod === 8 && typeof DecompressionStream !== "function") {
      setStatusMessage("Browser does not support DecompressionStream; cannot decompress this entry.");
      return;
    }
    const originalText = target.textContent;
    if (buttonTarget) {
      buttonTarget.disabled = true;
      buttonTarget.textContent = entry.compressionMethod === 8 ? "Decompressing..." : "Preparing...";
    }
    try {
      const compressedBlob = await sliceZipEntryBlob(file, entry);
      const blob = await decompressZipEntry(entry, compressedBlob);
      triggerDownload(blob, sanitizeDownloadName(entry));
      setStatusMessage(null);
    } catch (error) {
      const message = error instanceof Error && error.message ? error.message : String(error);
      setStatusMessage(`Extract failed: ${message}`);
    } finally {
      if (buttonTarget) {
        buttonTarget.disabled = false;
        buttonTarget.textContent = originalText || "Extract";
      }
    }
  };

export { createZipEntryClickHandler };
