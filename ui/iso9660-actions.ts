"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { formatHumanSize } from "../binary-utils.js";
import { safe } from "../html-utils.js";
import { scanDirectoryBytes } from "../analyzers/iso9660/directory-records.js";
import type { Iso9660StringEncoding } from "../analyzers/iso9660/types.js";
import { renderIso9660DirectoryListing } from "./iso9660-directory-listing.js";

type Iso9660Deps = {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
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

const createIso9660EntryClickHandler = ({ getParseResult, getFile, setStatusMessage }: Iso9660Deps) =>
  async (event: Event): Promise<void> => {
    const target = event.target;
    if (!(target instanceof Element)) return;

    const extractButton = target.closest("button.isoExtractButton");
    const dirButton = extractButton ? null : target.closest("button.isoDirToggleButton");
    let button: HTMLButtonElement | null = null;
    if (extractButton instanceof HTMLButtonElement) {
      button = extractButton;
    } else if (dirButton instanceof HTMLButtonElement) {
      button = dirButton;
    }
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
      const lba = parseNumberAttr(button.getAttribute("data-iso-lba"));
      const declaredSize = parseNumberAttr(button.getAttribute("data-iso-size"));
      const path = button.getAttribute("data-iso-path") || "/";
      const depth = parseNumberAttr(button.getAttribute("data-iso-depth")) || 0;
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

      const originalText = button.textContent;
      button.disabled = true;
      button.textContent = "Loading...";
      try {
        const issues: string[] = [];
        const pushIssue = (message: string): void => {
          if (issues.length < MAX_DIRECTORY_ISSUES) issues.push(String(message));
        };

        const offset = lba * iso.selectedBlockSize;
        const size = declaredSize != null && declaredSize > 0 ? declaredSize : iso.selectedBlockSize;
        const available = Math.max(0, file.size - offset);
        const bytesToRead = Math.min(size, available, MAX_DIRECTORY_BYTES);
        if (bytesToRead <= 0) {
          container.innerHTML = `<div class="smallNote">${safe("Directory is outside the file bounds.")}</div>`;
          setStatusMessage("Directory is outside the file bounds.");
          row.hidden = false;
          return;
        }
        if (size > bytesToRead) {
          pushIssue(
            `Directory is large (${formatHumanSize(size)}); only first ${formatHumanSize(bytesToRead)} scanned.`
          );
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
        button.textContent = "Collapse";
        setStatusMessage(null);
      } catch (error) {
        const message = error instanceof Error && error.message ? error.message : String(error);
        container.innerHTML = `<div class="smallNote">${safe(message)}</div>`;
        setStatusMessage(`Directory read failed: ${message}`);
      } finally {
        button.disabled = false;
        if (button.textContent === "Loading...") {
          button.textContent = originalText || "Expand";
        }
      }
      return;
    }

    if (action !== "extract") return;

    const directOffset = parseNumberAttr(button.getAttribute("data-iso-offset"));
    const directLength = parseNumberAttr(button.getAttribute("data-iso-length"));
    const directName = button.getAttribute("data-iso-name");
    const directFlags = parseNumberAttr(button.getAttribute("data-iso-flags"));

    let offset: number | null = null;
    let length: number | null = null;
    let suggestedName: string | null = null;
    let fileFlags: number | null = directFlags;

    if (directOffset != null && directLength != null) {
      offset = directOffset;
      length = directLength;
      suggestedName = directName;
    } else {
      const root = iso.rootDirectory;
      if (!root) {
        setStatusMessage("ISO-9660 root directory was not parsed.");
        return;
      }
      const entryIndex = parseNumberAttr(button.getAttribute("data-iso-entry"));
      if (entryIndex == null) return;
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
      offset = entry.extentLocationLba * iso.selectedBlockSize;
      length = entry.dataLength;
      suggestedName = entry.name;
      fileFlags = entry.fileFlags;
    }

    if (fileFlags != null && (fileFlags & 0x80) !== 0) {
      setStatusMessage("Multi-extent ISO-9660 files are not supported for extraction yet.");
      return;
    }
    if (offset == null || length == null) return;

    const file = getFile();
    if (!file) {
      setStatusMessage("No file selected.");
      return;
    }

    const end = offset + length;
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
      triggerDownload(blob, sanitizeDownloadName(suggestedName || "entry.bin"));
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
