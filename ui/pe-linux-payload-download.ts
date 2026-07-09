"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { isPeWindowsParseResult } from "../analyzers/pe/index.js";

type PeLinuxPayloadDownloadDeps = {
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

const isKnownLinuxPayloadRange = (
  parseResult: ParseForUiResult,
  start: number,
  end: number
): boolean => {
  if (parseResult.analyzer !== "pe" || !parseResult.parsed || !isPeWindowsParseResult(parseResult.parsed)) {
    return false;
  }
  const payload = parseResult.parsed.linuxBoot?.payload;
  return payload != null && start === payload.fileOffset && end === payload.endOffset;
};

const getLinuxPayload = (parseResult: ParseForUiResult) =>
  parseResult.analyzer === "pe" &&
  parseResult.parsed &&
  isPeWindowsParseResult(parseResult.parsed)
    ? parseResult.parsed.linuxBoot?.payload
    : undefined;

const extensionForFormat = (format: string): string =>
  format === "gzip" ? "gz" : "bin";

const mimeForFormat = (format: string): string =>
  format === "gzip" ? "application/gzip" : "application/octet-stream";

export const createPeLinuxPayloadDownloadClickHandler =
  ({ getParseResult, getFile, setStatusMessage }: PeLinuxPayloadDownloadDeps) =>
  (event: Event): void => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest("[data-pe-linux-payload-download]");
    if (!(button instanceof HTMLElement)) return;
    const file = getFile();
    if (!file) {
      setStatusMessage("No file selected.");
      return;
    }
    const start = parseOffsetAttribute(button, "data-linux-payload-start");
    const end = parseOffsetAttribute(button, "data-linux-payload-end");
    const parseResult = getParseResult();
    const payload = getLinuxPayload(parseResult);
    const hasMatchingRange =
      start != null && end != null && isKnownLinuxPayloadRange(parseResult, start, end);
    if (start == null || end == null || end <= start || end > file.size || !payload || !hasMatchingRange) {
      setStatusMessage("Linux payload range is not available.");
      return;
    }
    triggerDownload(
      file.slice(start, end, mimeForFormat(payload.format)),
      `${sanitizeBaseName(file.name)}.linux-payload-${start.toString(16)}-${end.toString(16)}.` +
      `${extensionForFormat(payload.format)}`
    );
    setStatusMessage(null);
  };
