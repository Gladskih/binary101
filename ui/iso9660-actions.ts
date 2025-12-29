"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";

type Iso9660Deps = {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
};

const sanitizeDownloadName = (name: string): string => {
  const parts = name.split(/[\\/]/);
  const last = parts[parts.length - 1] || "";
  const trimmed = last.trim();
  return trimmed.length ? trimmed : "entry.bin";
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

const createIso9660EntryClickHandler = ({ getParseResult, getFile, setStatusMessage }: Iso9660Deps) =>
  async (event: Event): Promise<void> => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest("button.isoExtractButton");
    if (!(button instanceof HTMLButtonElement)) return;
    const action = button.getAttribute("data-iso-action");
    if (action !== "extract") return;
    const entryAttr = button.getAttribute("data-iso-entry");
    if (!entryAttr) return;
    const entryIndex = Number.parseInt(entryAttr, 10);
    if (Number.isNaN(entryIndex)) return;

    const parseResult = getParseResult();
    if (parseResult.analyzer !== "iso9660") {
      setStatusMessage("Not an ISO-9660 file.");
      return;
    }
    const iso = parseResult.parsed;
    const root = iso.rootDirectory;
    if (!root) {
      setStatusMessage("ISO-9660 root directory was not parsed.");
      return;
    }
    const entry = root.entries[entryIndex];
    if (!entry) {
      setStatusMessage("ISO-9660 entry not found.");
      return;
    }
    if (entry.kind !== "file") {
      setStatusMessage("Selected ISO-9660 entry is not a file.");
      return;
    }
    if (entry.extentLocationLba == null || entry.dataLength == null) {
      setStatusMessage("ISO-9660 entry data bounds are missing.");
      return;
    }
    if ((entry.fileFlags & 0x80) !== 0) {
      setStatusMessage("Multi-extent ISO-9660 files are not supported for extraction yet.");
      return;
    }

    const file = getFile();
    if (!file) {
      setStatusMessage("No file selected.");
      return;
    }

    const offset = entry.extentLocationLba * iso.selectedBlockSize;
    const end = offset + entry.dataLength;
    if (!Number.isFinite(offset) || offset < 0) {
      setStatusMessage("ISO-9660 entry offset is invalid.");
      return;
    }
    if (!Number.isFinite(end) || end < offset) {
      setStatusMessage("ISO-9660 entry length is invalid.");
      return;
    }
    if (offset >= file.size) {
      setStatusMessage("ISO-9660 entry starts past end of file.");
      return;
    }

    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Preparing...";
    try {
      const blob = file.slice(offset, end);
      triggerDownload(blob, sanitizeDownloadName(entry.name));
      setStatusMessage(null);
    } catch (error) {
      const message = error instanceof Error && error.message ? error.message : String(error);
      setStatusMessage(`Extract failed: ${message}`);
    } finally {
      button.disabled = false;
      button.textContent = originalText || "Download";
    }
  };

export { createIso9660EntryClickHandler };

