"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { isPeWindowsParseResult } from "../analyzers/pe/index.js";
import type { PePayloadFormat } from "../analyzers/pe/payloads.js";

type PePayloadDownloadDeps = {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
};

const FORMAT_DETAILS: Readonly<Record<PePayloadFormat, { extension: string; mediaType: string }>> = {
  rar: { extension: "rar", mediaType: "application/vnd.rar" },
  sevenzip: { extension: "7z", mediaType: "application/x-7z-compressed" }
};

const parseOffset = (button: HTMLElement, name: string): number | null => {
  const value = button.getAttribute(name);
  if (value == null || !/^\d+$/.test(value)) return null;
  const offset = Number(value);
  return Number.isSafeInteger(offset) && offset >= 0 ? offset : null;
};

const parseFormat = (button: HTMLElement): PePayloadFormat | null => {
  const format = button.getAttribute("data-payload-format");
  return format === "rar" || format === "sevenzip" ? format : null;
};

const sanitizeBaseName = (name: string): string =>
  name.split(/[\\/]/).pop()?.trim().replace(/[^a-z0-9._-]+/gi, "_") || "file";

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

const hasValidatedPayload = (
  result: ParseForUiResult,
  start: number,
  end: number,
  format: PePayloadFormat
): boolean => {
  if (result.analyzer !== "pe" || !result.parsed || !isPeWindowsParseResult(result.parsed)) {
    return false;
  }
  return result.parsed.payloads?.entries.some(payload =>
    payload.start === start && payload.end === end && payload.format === format
  ) ?? false;
};

export const createPePayloadDownloadClickHandler =
  ({ getParseResult, getFile, setStatusMessage }: PePayloadDownloadDeps) =>
  (event: Event): void => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest("[data-pe-payload-download]");
    if (!(button instanceof HTMLElement)) return;
    const file = getFile();
    if (!file) {
      setStatusMessage("No file selected.");
      return;
    }
    const start = parseOffset(button, "data-payload-start");
    const end = parseOffset(button, "data-payload-end");
    const format = parseFormat(button);
    if (start == null || end == null || end <= start || !format ||
        !hasValidatedPayload(getParseResult(), start, end, format)) {
      setStatusMessage("PE payload is not available.");
      return;
    }
    const details = FORMAT_DETAILS[format];
    triggerDownload(
      file.slice(start, end, details.mediaType),
      `${sanitizeBaseName(file.name)}.payload-${start.toString(16)}.${details.extension}`
    );
    setStatusMessage(null);
  };
