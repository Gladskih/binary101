"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";

type GzipDeps = {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
};

const sanitizeDownloadName = (name: string): string => {
  const parts = name.split(/[\\/]/);
  const last = parts[parts.length - 1] || "";
  const trimmed = last.trim();
  return trimmed.length ? trimmed : "decompressed.bin";
};

const stripGzipExtension = (name: string): string => {
  const lower = name.toLowerCase();
  if (lower.endsWith(".tgz")) {
    return name.slice(0, -4) + ".tar";
  }
  if (lower.endsWith(".gz")) {
    const stripped = name.slice(0, -3);
    return stripped.length ? stripped : "decompressed.bin";
  }
  return name;
};

const suggestOutputName = (file: File, parseResult: ParseForUiResult): string => {
  if (parseResult.analyzer === "gzip") {
    const headerName = parseResult.parsed?.header?.fileName;
    if (typeof headerName === "string" && headerName.trim().length) {
      return sanitizeDownloadName(headerName);
    }
  }
  const base = typeof file.name === "string" && file.name.trim().length ? file.name.trim() : "decompressed.bin";
  return sanitizeDownloadName(stripGzipExtension(base));
};

const decompressGzipToBlob = async (file: File): Promise<Blob> => {
  if (typeof DecompressionStream !== "function") {
    throw new Error("Browser does not support DecompressionStream for gzip.");
  }
  const stream = file.stream().pipeThrough(new DecompressionStream("gzip"));
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

const createGzipClickHandler = ({ getParseResult, getFile, setStatusMessage }: GzipDeps) =>
  async (event: Event): Promise<void> => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest("button.gzipDecompressButton");
    if (!(button instanceof HTMLButtonElement)) return;
    const action = button.getAttribute("data-gzip-action");
    if (action !== "decompress") return;

    const parseResult = getParseResult();
    if (parseResult.analyzer !== "gzip") {
      setStatusMessage("Not a gzip file.");
      return;
    }
    const file = getFile();
    if (!file) {
      setStatusMessage("No file selected.");
      return;
    }
    if (typeof DecompressionStream !== "function") {
      setStatusMessage("Browser does not support DecompressionStream; cannot decompress gzip.");
      return;
    }

    const suggestedName = suggestOutputName(file, parseResult);
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Decompressing...";
    try {
      const blob = await decompressGzipToBlob(file);
      triggerDownload(blob, suggestedName);
      setStatusMessage(null);
    } catch (error) {
      const message = error instanceof Error && error.message ? error.message : String(error);
      setStatusMessage(`Decompression failed: ${message}`);
    } finally {
      button.disabled = false;
      button.textContent = originalText || "Decompress";
    }
  };

export { createGzipClickHandler };

