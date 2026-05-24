"use strict";

import { detectBinaryType } from "../analyzers/index.js";
import { formatAccessError } from "./directory-handles.js";
import { setFileMetadataCells, setUnreadableFileCells } from "./directory-table-rendering.js";
import type { DirectoryFileRow, DirectoryRow } from "./directory-handles.js";
import type { DirectoryFileCells } from "./directory-table-rendering.js";

type FileTypeDetector = (file: File) => Promise<string>;
type TimeSource = () => number;

interface DirectoryFileScanConfig {
  progressWrapElement: HTMLElement;
  progressElement: HTMLProgressElement;
  progressTextElement: HTMLElement;
  detectFileType?: FileTypeDetector;
  now?: TimeSource;
  yieldToBrowser?: () => Promise<void>;
}

interface ProgressState {
  readonly startMs: number;
  measuredFiles: number;
  measuredMs: number;
  visible: boolean;
}

// One second is the requested UX threshold; the live per-file average decides the file count.
const NOTICEABLE_SCAN_MS = 1000;

const updateProgress = (
  config: DirectoryFileScanConfig,
  totalFiles: number,
  processedFiles: number,
  state: ProgressState,
  lastFileMs: number
): void => {
  if (processedFiles <= 0 || totalFiles <= 0) return;
  state.measuredFiles += 1;
  state.measuredMs += Math.max(0, lastFileMs);
  const averageMs = state.measuredFiles > 0 ? state.measuredMs / state.measuredFiles : 0;
  const elapsedMs = (config.now ?? performance.now.bind(performance))() - state.startMs;
  const predictedScanMs = averageMs * totalFiles;
  state.visible ||=
    processedFiles < totalFiles && (predictedScanMs >= NOTICEABLE_SCAN_MS || elapsedMs >= NOTICEABLE_SCAN_MS);
  config.progressWrapElement.hidden = !state.visible;
  config.progressElement.max = totalFiles;
  config.progressElement.value = processedFiles;
  config.progressTextElement.textContent = `Scanned ${processedFiles} / ${totalFiles} files`;
};

const scanDirectoryFileRows = async (
  config: DirectoryFileScanConfig,
  rows: readonly DirectoryRow[],
  fileCells: ReadonlyMap<string, DirectoryFileCells>,
  isCurrent: () => boolean
): Promise<number | null> => {
  const files = rows.filter((row): row is DirectoryFileRow => row.kind === "file");
  const now = config.now ?? performance.now.bind(performance);
  const state: ProgressState = { startMs: now(), measuredFiles: 0, measuredMs: 0, visible: false };
  const detector = config.detectFileType ?? detectBinaryType;
  for (let index = 0; index < files.length; index += 1) {
    if (!isCurrent()) return null;
    const row = files[index];
    if (!row) continue;
    const startedMs = now();
    const cells = fileCells.get(row.path);
    if (!cells) continue;
    try {
      const file = await row.handle.getFile();
      setFileMetadataCells(cells, file);
      try {
        cells.typeCell.textContent = await detector(file);
      } catch (error) {
        cells.typeCell.textContent = `Unable to detect: ${formatAccessError(error)}`;
      }
    } catch (error) {
      setUnreadableFileCells(cells, formatAccessError(error));
    }
    updateProgress(config, files.length, index + 1, state, now() - startedMs);
    await (config.yieldToBrowser ?? (() => new Promise<void>(resolve => setTimeout(resolve, 0))))();
  }
  return files.length;
};

export { scanDirectoryFileRows };
export type { DirectoryFileScanConfig };
