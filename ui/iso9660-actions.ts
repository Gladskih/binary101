"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { formatHumanSize } from "../binary-utils.js";
import { escapeHtml } from "../html-utils.js";
import { scanDirectoryBytes } from "../analyzers/iso9660/directory-records.js";
import type { Iso9660StringEncoding } from "../analyzers/iso9660/types.js";
import { renderIso9660DirectoryListing } from "./iso9660-directory-listing.js";

type Iso9660Deps = {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
};

type Iso9660ExtractionBounds = {
  offset: number; length: number;
  suggestedName: string | null; fileFlags: number | null;
};

const MAX_DIRECTORY_BYTES = 4 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES = 5000;
const MAX_DIRECTORY_ISSUES = 100;

const sanitizeDownloadName = (name: string): string => {
  const parts = name.split(/[\\/]/);
  const last = parts[parts.length - 1] || "";
  const trimmed = last.trim();
  return trimmed.length ? trimmed : "entry.bin";
};

const parseNumberAttr = (value: string | null): number | null => {
  if (!value) return null;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : null;
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

const findIso9660ActionButton = (target: EventTarget | null): HTMLButtonElement | null => {
  if (!(target instanceof Element)) return null;
  const extractButton = target.closest("button.isoExtractButton");
  const dirButton = extractButton ? null : target.closest("button.isoDirToggleButton");
  if (extractButton instanceof HTMLButtonElement) return extractButton;
  return dirButton instanceof HTMLButtonElement ? dirButton : null;
};

const renderIso9660Directory = async (
  button: HTMLButtonElement,
  file: File,
  iso: Extract<ParseForUiResult, { analyzer: "iso9660" }>["parsed"],
  setStatusMessage: Iso9660Deps["setStatusMessage"]
): Promise<void> => {
  const lba = parseNumberAttr(button.getAttribute("data-iso-lba"));
  const targetId = button.getAttribute("data-iso-target");
  if (lba == null || !targetId) return;
  const container = document.getElementById(targetId);
  if (!container) return;
  const row = container.closest("tr");
  if (!row) return;
  if (!row.hidden) {
    row.hidden = true;
    button.textContent = "Expand";
    return;
  }
  row.hidden = false;
  if (container.getAttribute("data-iso-loaded") === "1") {
    button.textContent = "Collapse";
    return;
  }
  await loadIso9660Directory(button, file, iso, container, setStatusMessage);
};

const loadIso9660Directory = async (
  button: HTMLButtonElement,
  file: File,
  iso: Extract<ParseForUiResult, { analyzer: "iso9660" }>["parsed"],
  container: HTMLElement,
  setStatusMessage: Iso9660Deps["setStatusMessage"]
): Promise<void> => {
  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = "Loading...";
  try {
    const issues: string[] = [];
    const pushIssue = (message: string): void => {
      if (issues.length < MAX_DIRECTORY_ISSUES) issues.push(String(message));
    };
    const loaded = await scanAndRenderIso9660Directory(
      file,
      iso,
      button,
      container,
      issues,
      pushIssue
    );
    if (!loaded) {
      setStatusMessage("Directory is outside the file bounds.");
      return;
    }
    button.textContent = "Collapse";
    setStatusMessage(null);
  } catch (error) {
    const message = error instanceof Error && error.message ? error.message : String(error);
    container.innerHTML = `<div class="smallNote">${escapeHtml(message)}</div>`;
    setStatusMessage(`Directory read failed: ${message}`);
  } finally {
    button.disabled = false;
    if (button.textContent === "Loading...") button.textContent = originalText || "Expand";
  }
};

const scanAndRenderIso9660Directory = async (
  file: File,
  iso: Extract<ParseForUiResult, { analyzer: "iso9660" }>["parsed"],
  button: HTMLButtonElement,
  container: HTMLElement,
  issues: string[],
  pushIssue: (message: string) => void
): Promise<boolean> => {
  const lba = parseNumberAttr(button.getAttribute("data-iso-lba")) ?? 0;
  const declaredSize = parseNumberAttr(button.getAttribute("data-iso-size"));
  const path = button.getAttribute("data-iso-path") || "/";
  const depth = parseNumberAttr(button.getAttribute("data-iso-depth")) || 0;
  const targetId = button.getAttribute("data-iso-target") || "";
  const offset = lba * iso.selectedBlockSize;
  const size = declaredSize != null && declaredSize > 0 ? declaredSize : iso.selectedBlockSize;
  const available = Math.max(0, file.size - offset);
  const bytesToRead = Math.min(size, available, MAX_DIRECTORY_BYTES);
  if (bytesToRead <= 0) {
    container.innerHTML = `<div class="smallNote">${escapeHtml("Directory is outside the file bounds.")}</div>`;
    return false;
  }
  if (size > bytesToRead) {
    pushIssue(`Directory is large (${formatHumanSize(size)}); only first ${formatHumanSize(bytesToRead)} scanned.`);
  }
  const bytes = new Uint8Array(await file.slice(offset, offset + bytesToRead).arrayBuffer());
  const scan = scanDirectoryBytes({
    bytes,
    absoluteBaseOffset: offset,
    blockSize: iso.selectedBlockSize,
    encoding: iso.selectedEncoding as Iso9660StringEncoding,
    pushIssue,
    maxEntries: MAX_DIRECTORY_ENTRIES
  });
  container.innerHTML = renderIso9660DirectoryListing({
    entries: scan.entries,
    totalEntries: scan.totalEntries,
    omittedEntries: scan.omittedEntries,
    bytesRead: bytes.length,
    declaredSize: size,
    directoryPath: path,
    depth,
    isoBlockSize: iso.selectedBlockSize,
    containerIdPrefix: targetId,
    issues
  });
  container.setAttribute("data-iso-loaded", "1");
  return true;
};

const getIso9660ExtractionBounds = (
  button: HTMLButtonElement,
  iso: Extract<ParseForUiResult, { analyzer: "iso9660" }>["parsed"],
  setStatusMessage: Iso9660Deps["setStatusMessage"]
): Iso9660ExtractionBounds | null => {
  const directOffset = parseNumberAttr(button.getAttribute("data-iso-offset"));
  const directLength = parseNumberAttr(button.getAttribute("data-iso-length"));
  const directName = button.getAttribute("data-iso-name");
  const directFlags = parseNumberAttr(button.getAttribute("data-iso-flags"));
  if (directOffset != null && directLength != null) {
    return { offset: directOffset, length: directLength, suggestedName: directName, fileFlags: directFlags };
  }
  const root = iso.rootDirectory;
  if (!root) {
    setStatusMessage("ISO-9660 root directory was not parsed.");
    return null;
  }
  const entryIndex = parseNumberAttr(button.getAttribute("data-iso-entry"));
  if (entryIndex == null) return null;
  const entry = root.entries[entryIndex];
  if (!entry) {
    setStatusMessage("ISO-9660 entry not found.");
    return null;
  }
  if (entry.kind !== "file") {
    setStatusMessage("Selected ISO-9660 entry is not a file.");
    return null;
  }
  if (entry.extentLocationLba == null || entry.dataLength == null) {
    setStatusMessage("ISO-9660 entry data bounds are missing.");
    return null;
  }
  return {
    offset: entry.extentLocationLba * iso.selectedBlockSize,
    length: entry.dataLength,
    suggestedName: entry.name,
    fileFlags: entry.fileFlags
  };
};

const extractIso9660Entry = async (
  button: HTMLButtonElement,
  file: File,
  bounds: Iso9660ExtractionBounds,
  setStatusMessage: Iso9660Deps["setStatusMessage"]
): Promise<void> => {
  const end = bounds.offset + bounds.length;
  if (!Number.isFinite(bounds.offset) || bounds.offset < 0) {
    setStatusMessage("ISO-9660 entry offset is invalid.");
    return;
  }
  if (!Number.isFinite(end) || end < bounds.offset) {
    setStatusMessage("ISO-9660 entry length is invalid.");
    return;
  }
  if (bounds.offset >= file.size) {
    setStatusMessage("ISO-9660 entry starts past end of file.");
    return;
  }
  await downloadIso9660Entry(button, file, bounds.offset, end, bounds.suggestedName, setStatusMessage);
};

const startIso9660Extraction = async (
  button: HTMLButtonElement,
  getFile: Iso9660Deps["getFile"],
  iso: Extract<ParseForUiResult, { analyzer: "iso9660" }>["parsed"],
  setStatusMessage: Iso9660Deps["setStatusMessage"]
): Promise<void> => {
  const bounds = getIso9660ExtractionBounds(button, iso, setStatusMessage);
  if (!bounds) return;
  if (bounds.fileFlags != null && (bounds.fileFlags & 0x80) !== 0) {
    setStatusMessage("Multi-extent ISO-9660 files are not supported for extraction yet.");
    return;
  }
  const file = getFile();
  if (!file) {
    setStatusMessage("No file selected.");
    return;
  }
  await extractIso9660Entry(button, file, bounds, setStatusMessage);
};

const downloadIso9660Entry = async (
  button: HTMLButtonElement,
  file: File,
  offset: number,
  end: number,
  suggestedName: string | null,
  setStatusMessage: Iso9660Deps["setStatusMessage"]
): Promise<void> => {
  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = "Preparing...";
  try {
    triggerDownload(file.slice(offset, end), sanitizeDownloadName(suggestedName || "entry.bin"));
    setStatusMessage(null);
  } catch (error) {
    const message = error instanceof Error && error.message ? error.message : String(error);
    setStatusMessage(`Extract failed: ${message}`);
  } finally {
    button.disabled = false;
    button.textContent = originalText || "Download";
  }
};

const createIso9660EntryClickHandler = ({ getParseResult, getFile, setStatusMessage }: Iso9660Deps) =>
  async (event: Event): Promise<void> => {
    const button = findIso9660ActionButton(event.target);
    if (!button) return;
    const parseResult = getParseResult();
    if (parseResult.analyzer !== "iso9660") {
      setStatusMessage("Not an ISO-9660 file.");
      return;
    }
    const iso = parseResult.parsed;
    const action = button.getAttribute("data-iso-action");
    if (action === "toggle-dir") {
      const file = getFile();
      if (!file) {
        setStatusMessage("No file selected.");
        return;
      }
      await renderIso9660Directory(button, file, iso, setStatusMessage);
      return;
    }
    if (action !== "extract") return;
    await startIso9660Extraction(button, getFile, iso, setStatusMessage);
  };

export { createIso9660EntryClickHandler };
