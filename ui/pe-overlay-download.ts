"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { isPeWindowsParseResult } from "../analyzers/pe/index.js";

type PeOverlayDownloadDeps = {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
};

const sanitizeBaseName = (name: string): string => {
  const raw = name.split(/[\\/]/).pop()?.trim() || "file";
  return raw.replace(/[^a-z0-9._-]+/gi, "_") || "file";
};

const parseOffsetAttribute = (button: HTMLElement, name: string): number | null => {
  const value = button.getAttribute(name);
  if (value == null || !/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
};

const triggerDownload = (blob: Blob, filename: string): void => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

const isKnownOverlayDownloadRange = (
  parseResult: ParseForUiResult,
  start: number,
  end: number
): boolean => {
  const ranges = parseResult.analyzer === "pe" ? parseResult.parsed?.overlay?.ranges ?? [] : [];
  const isOverlayRange = ranges.some(range =>
    (range.start === start && range.end === end) ||
    range.findings.some(finding => finding.start === start && finding.end === end)
  );
  const parsed = parseResult.analyzer === "pe" ? parseResult.parsed : null;
  if (isOverlayRange || !parsed || !isPeWindowsParseResult(parsed)) return isOverlayRange;
  return parsed.packers?.reports
    .find(report => report.id === "nsis-installer")
    ?.findings.some(finding =>
      finding.id === "nsis-installer" &&
      finding.firstHeaderOffset === start &&
      finding.firstHeaderOffset + finding.followingDataSize === end
    ) ?? false;
};

export const createPeOverlayDownloadClickHandler =
  ({ getParseResult, getFile, setStatusMessage }: PeOverlayDownloadDeps) =>
  (event: Event): void => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest("[data-pe-overlay-download]");
    if (!(button instanceof HTMLElement)) return;
    const file = getFile();
    if (!file) {
      setStatusMessage("No file selected.");
      return;
    }
    const start = parseOffsetAttribute(button, "data-overlay-start");
    const end = parseOffsetAttribute(button, "data-overlay-end");
    const parseResult = getParseResult();
    const hasMatchingRange = start != null && end != null && isKnownOverlayDownloadRange(parseResult, start, end);
    if (start == null || end == null || end <= start || !hasMatchingRange) {
      setStatusMessage("PE overlay range is not available.");
      return;
    }
    triggerDownload(
      file.slice(start, end, "application/octet-stream"),
      `${sanitizeBaseName(file.name)}.overlay-${start.toString(16)}-${end.toString(16)}.bin`
    );
    setStatusMessage(null);
  };
