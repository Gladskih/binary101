"use strict";

import { formatHumanSize } from "../binary-utils.js";
import { createFileRangeReader, type FileRangeReader } from "../analyzers/file-range-reader.js";
import type { ParseForUiResult } from "../analyzers/index.js";
import type {
  PeOverlayRange,
  PeOverlayScanOptions,
  PeOverlayScanProgress
} from "../analyzers/pe/overlay.js";
import type { PeParseResult } from "../analyzers/pe/index.js";
import { scanPeOverlayRange } from "../analyzers/pe/overlay-scan.js";

type ScanPeOverlayRange = (
  file: File,
  reader: FileRangeReader,
  range: PeOverlayRange,
  options: PeOverlayScanOptions
) => Promise<PeOverlayRange>;

type PeOverlayScanControllerOptions = {
  getCurrentFile: () => File | null;
  getCurrentParseResult: () => ParseForUiResult;
  renderPanel?: (pe: PeParseResult) => void;
  renderResult?: (result: ParseForUiResult) => void;
  setStatusMessage: (message: string | null | undefined) => void;
  scan?: ScanPeOverlayRange;
};

export type PeOverlayScanController = {
  cancel: () => void;
  start: (file: File, range: PeOverlayRange) => void;
};

export type PeOverlayScanActions = PeOverlayScanController & {
  handleClick: (targetElement: Element | null) => boolean;
};

const parseOffsetAttribute = (button: Element, name: string): number | null => {
  const value = button.getAttribute(name);
  if (!value) return null;
  const offset = Number(value);
  return Number.isSafeInteger(offset) && offset >= 0 ? offset : null;
};

const overlayScanElementId = (range: PeOverlayRange, suffix: string): string =>
  `peOverlayScan_${range.start}_${range.end}_${suffix}`;

const setOverlayScanUiState = (range: PeOverlayRange, state: "busy" | "idle"): void => {
  const isBusy = state === "busy";
  const button = document.getElementById(overlayScanElementId(range, "button"));
  if (button && "disabled" in button) (button as HTMLButtonElement).disabled = isBusy;
  const cancelButton = document.getElementById(overlayScanElementId(range, "cancel"));
  if (cancelButton && "hidden" in cancelButton) (cancelButton as HTMLElement).hidden = !isBusy;
  const progress = document.getElementById(overlayScanElementId(range, "progress"));
  if (progress && "hidden" in progress) (progress as HTMLElement).hidden = !isBusy;
};

const updateOverlayScanProgress = (range: PeOverlayRange, progress: PeOverlayScanProgress): void => {
  const progressElement = document.getElementById(overlayScanElementId(range, "progress"));
  if (progressElement instanceof HTMLProgressElement) {
    progressElement.max = Math.max(1, progress.totalBytes);
    progressElement.value = Math.min(progress.totalBytes, progress.bytesScanned);
  }
  const text = document.getElementById(overlayScanElementId(range, "text"));
  if (text instanceof HTMLElement) {
    const percent = progress.totalBytes > 0
      ? Math.round((progress.bytesScanned / progress.totalBytes) * 100)
      : 0;
    text.textContent =
      `${progress.stage === "done" ? "Done." : "Scanning..."} ${percent}% ` +
      `(${formatHumanSize(progress.bytesScanned)} / ${formatHumanSize(progress.totalBytes)}), ` +
      `${progress.findingsFound} finding${progress.findingsFound === 1 ? "" : "s"}.`;
  }
};

const findOverlayRange = (
  parseResult: ParseForUiResult,
  start: number,
  end: number
): PeOverlayRange | null =>
  parseResult.analyzer === "pe"
    ? parseResult.parsed?.overlay?.ranges.find(range => range.start === start && range.end === end) ?? null
    : null;

export const createPeOverlayScanController = (
  opts: PeOverlayScanControllerOptions
): PeOverlayScanController => {
  let abortController: AbortController | null = null;
  let activeRange: PeOverlayRange | null = null;
  let runId = 0;
  const scan = opts.scan ?? scanPeOverlayRange;

  const cancel = (): void => {
    runId++;
    const cancelledRange = activeRange;
    if (!abortController) return;
    abortController.abort();
    abortController = null;
    activeRange = null;
    if (cancelledRange) setOverlayScanUiState(cancelledRange, "idle");
    opts.setStatusMessage("PE overlay scan cancelled.");
  };

  const start = (file: File, range: PeOverlayRange): void => {
    cancel();
    setOverlayScanUiState(range, "busy");
    const localRunId = ++runId;
    const localAbortController = new AbortController();
    abortController = localAbortController;
    activeRange = range;
    updateOverlayScanProgress(range, {
      stage: "scanning",
      bytesScanned: 0,
      totalBytes: range.size,
      findingsFound: 0
    });
    void (async () => {
      try {
        const scannedRange = await scan(file, createFileRangeReader(file, 0, file.size), range, {
          signal: localAbortController.signal,
          onProgress: progress => {
            if (localRunId === runId) updateOverlayScanProgress(range, progress);
          }
        });
        if (localRunId !== runId || localAbortController.signal.aborted) return;
        if (opts.getCurrentFile() !== file) return;
        const current = opts.getCurrentParseResult();
        const currentRange = findOverlayRange(current, range.start, range.end);
        if (!currentRange || current.analyzer !== "pe" || !current.parsed?.overlay) return;
        current.parsed.overlay.ranges = current.parsed.overlay.ranges.map(candidate =>
          candidate.start === range.start && candidate.end === range.end ? scannedRange : candidate
        );
        abortController = null;
        activeRange = null;
        setOverlayScanUiState(range, "idle");
        if (opts.renderPanel) {
          opts.renderPanel(current.parsed);
        } else {
          opts.renderResult?.(current);
        }
        opts.setStatusMessage(`PE overlay scan complete: ${scannedRange.findings.length} finding(s).`);
      } catch (error) {
        if (localAbortController.signal.aborted) return;
        abortController = null;
        activeRange = null;
        setOverlayScanUiState(range, "idle");
        const message = error instanceof Error && error.message ? error.message : String(error);
        opts.setStatusMessage(`PE overlay scan failed: ${message}`);
      }
    })();
  };

  return { cancel, start };
};

export const createPeOverlayScanActions = (
  opts: PeOverlayScanControllerOptions
): PeOverlayScanActions => {
  const controller = createPeOverlayScanController(opts);
  const handleClick = (targetElement: Element | null): boolean => {
    if (targetElement?.closest("[data-pe-overlay-scan-cancel]")) {
      controller.cancel();
      return true;
    }
    const buttonRange = readPeOverlayScanButtonRange(targetElement);
    if (!buttonRange) return false;
    const file = opts.getCurrentFile();
    if (!file) return true;
    const current = opts.getCurrentParseResult();
    const range = findOverlayRange(current, buttonRange.start, buttonRange.end);
    if (range) controller.start(file, range);
    return true;
  };
  return { ...controller, handleClick };
};

export const readPeOverlayScanButtonRange = (targetElement: Element | null): PeOverlayRange | null => {
  const button = targetElement?.closest("[data-pe-overlay-scan]");
  if (!(button instanceof Element)) return null;
  const start = parseOffsetAttribute(button, "data-overlay-start");
  const end = parseOffsetAttribute(button, "data-overlay-end");
  if (start == null || end == null || end <= start) return null;
  return { start, end, size: end - start, findings: [] };
};
