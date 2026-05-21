"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";

type PeDosNestedDownloadDeps = {
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

const isKnownNestedPeRange = (parseResult: ParseForUiResult, start: number, end: number): boolean => {
  if (parseResult.analyzer !== "pe" || !parseResult.parsed) return false;
  const nested = parseResult.parsed.dos.stub.code?.nestedPe;
  return nested != null && start === 0x40 + nested.offset && end === 0x40 + nested.endOffset;
};

export const createPeDosNestedDownloadClickHandler =
  ({ getParseResult, getFile, setStatusMessage }: PeDosNestedDownloadDeps) =>
  (event: Event): void => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest("[data-pe-dos-nested-download]");
    if (!(button instanceof HTMLElement)) return;
    const file = getFile();
    if (!file) {
      setStatusMessage("No file selected.");
      return;
    }
    const start = parseOffsetAttribute(button, "data-nested-start");
    const end = parseOffsetAttribute(button, "data-nested-end");
    const hasMatchingRange =
      start != null && end != null && isKnownNestedPeRange(getParseResult(), start, end);
    if (start == null || end == null || end <= start || !hasMatchingRange) {
      setStatusMessage("Nested PE range is not available.");
      return;
    }
    triggerDownload(
      file.slice(start, end, "application/vnd.microsoft.portable-executable"),
      `${sanitizeBaseName(file.name)}.dos-nested-${start.toString(16)}-${end.toString(16)}.exe`
    );
    setStatusMessage(null);
  };
