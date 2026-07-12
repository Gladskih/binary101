"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { createFileRangeReader } from "../analyzers/file-range-reader.js";
import { isPeWindowsParseResult } from "../analyzers/pe/index.js";
import { extractInnoSetupEngine } from "../analyzers/pe/packers/inno-setup-engine.js";
import type { PeInnoSetupFinding } from "../analyzers/pe/packers/index.js";

type InnoDownloadDeps = {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
};

const parseOffset = (button: HTMLElement): number | null => {
  const value = button.getAttribute("data-inno-table-offset");
  if (value == null || !/^\d+$/.test(value)) return null;
  const offset = Number(value);
  return Number.isSafeInteger(offset) && offset >= 0 ? offset : null;
};

const findFinding = (
  result: ParseForUiResult,
  tableOffset: number
): PeInnoSetupFinding | null => {
  if (result.analyzer !== "pe" || !result.parsed || !isPeWindowsParseResult(result.parsed)) return null;
  const finding = result.parsed.packers?.reports
    .find(report => report.id === "inno-setup")
    ?.findings.find(candidate =>
      candidate.id === "inno-setup" && candidate.offsetTableOffset === tableOffset
    );
  return finding?.id === "inno-setup" ? finding : null;
};

const downloadName = (file: File): string => {
  const base = file.name.split(/[\\/]/).pop()?.trim().replace(/[^a-z0-9._-]+/gi, "_") || "setup";
  return `${base}.inno-setup-engine.exe`;
};

const triggerDownload = (bytes: Uint8Array, filename: string): void => {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const blob = new Blob([copy.buffer], { type: "application/vnd.microsoft.portable-executable" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

export const createPeInnoSetupDownloadClickHandler =
  ({ getParseResult, getFile, setStatusMessage }: InnoDownloadDeps) =>
  async (event: Event): Promise<void> => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest("[data-pe-inno-engine-download]");
    if (!(button instanceof HTMLButtonElement)) return;
    const file = getFile();
    if (!file) {
      setStatusMessage("No file selected.");
      return;
    }
    const tableOffset = parseOffset(button);
    const finding = tableOffset == null ? null : findFinding(getParseResult(), tableOffset);
    if (!finding) {
      setStatusMessage("Inno Setup engine is not available.");
      return;
    }
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    try {
      const reader = createFileRangeReader(file, 0, file.size);
      triggerDownload(await extractInnoSetupEngine(reader, finding), downloadName(file));
      setStatusMessage(null);
    } catch (error) {
      setStatusMessage(`Inno Setup extraction failed: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  };
