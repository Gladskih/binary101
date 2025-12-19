import { formatHumanSize } from "../binary-utils.js";
import type { ParseForUiResult } from "../analyzers/index.js";
import type { ElfParseResult } from "../analyzers/elf/types.js";
import {
  analyzeElfInstructionSets,
  type AnalyzeElfInstructionSetOptions,
  type ElfInstructionSetProgress,
  type ElfInstructionSetReport
} from "../analyzers/elf/disassembly.js";

type AnalyzeElfInstructionSets = (
  file: File,
  opts: AnalyzeElfInstructionSetOptions
) => Promise<ElfInstructionSetReport>;

type ElfDisassemblyControllerOptions = {
  getCurrentFile: () => File | null;
  getCurrentParseResult: () => ParseForUiResult;
  renderResult: (result: ParseForUiResult) => void;
  analyze?: AnalyzeElfInstructionSets;
};

export type ElfDisassemblyController = {
  cancel: () => void;
  start: (file: File, elf: ElfParseResult) => void;
};

const ANALYZE_BUTTON_ID = "elfInstructionSetsAnalyzeButton";
const CANCEL_BUTTON_ID = "elfInstructionSetsCancelButton";
const PROGRESS_TEXT_ID = "elfInstructionSetsProgressText";
const PROGRESS_BAR_ID = "elfInstructionSetsProgress";
const CHIP_ID_PREFIX = "elfInstructionSetChip_";
const COUNT_ID_PREFIX = "elfInstructionSetCount_";

const setDisassemblyUiRunning = (running: boolean): void => {
  const analyzeButton = document.getElementById(ANALYZE_BUTTON_ID);
  if (analyzeButton && "disabled" in analyzeButton) {
    (analyzeButton as HTMLButtonElement).disabled = running;
  }

  const cancelButton = document.getElementById(CANCEL_BUTTON_ID);
  if (cancelButton && "hidden" in cancelButton) {
    (cancelButton as HTMLElement).hidden = !running;
  }

  const bar = document.getElementById(PROGRESS_BAR_ID);
  if (bar instanceof HTMLProgressElement) {
    bar.hidden = !running;
  }
};

const updateElfDisassemblyProgress = (progress: ElfInstructionSetProgress): void => {
  const bar = document.getElementById(PROGRESS_BAR_ID);
  const text = document.getElementById(PROGRESS_TEXT_ID);

  if (bar instanceof HTMLProgressElement) {
    bar.max = Math.max(1, progress.bytesSampled);
    if (progress.stage === "loading") {
      bar.removeAttribute("value");
    } else {
      bar.value = Math.min(progress.bytesSampled, progress.bytesDecoded);
    }
  }

  if (text instanceof HTMLElement) {
    const stageLabel =
      progress.stage === "loading"
        ? "Loading disassembler..."
        : progress.stage === "decoding"
          ? "Disassembling..."
          : "Done.";
    const percent =
      progress.bytesSampled > 0 ? Math.round((progress.bytesDecoded / progress.bytesSampled) * 100) : 0;
    const bytesText =
      progress.bytesSampled > 0
        ? `${formatHumanSize(progress.bytesDecoded)} / ${formatHumanSize(progress.bytesSampled)}`
        : "0 B";
    text.textContent = `${stageLabel} ${percent}% (${bytesText}), ${progress.instructionCount} instr., ${progress.invalidInstructionCount} invalid.`;
  }

  if (progress.knownFeatureCounts) {
    for (const [id, count] of Object.entries(progress.knownFeatureCounts)) {
      const countElement = document.getElementById(`${COUNT_ID_PREFIX}${id}`);
      if (countElement instanceof HTMLElement) {
        countElement.textContent = String(count);
        countElement.className = count > 0 ? "" : "dim";
      }

      const chipElement = document.getElementById(`${CHIP_ID_PREFIX}${id}`);
      if (chipElement instanceof HTMLElement) {
        chipElement.className = count > 0 ? "opt sel" : "opt dim";
      }
    }
  }
};

const setCancelled = (): void => {
  setDisassemblyUiRunning(false);
  const progressText = document.getElementById(PROGRESS_TEXT_ID);
  if (progressText instanceof HTMLElement) {
    progressText.textContent = "Cancelled.";
  }
};

export const createElfDisassemblyController = (
  opts: ElfDisassemblyControllerOptions
): ElfDisassemblyController => {
  let abortController: AbortController | null = null;
  let runId = 0;
  const analyze = opts.analyze ?? analyzeElfInstructionSets;

  const cancel = (): void => {
    runId++;
    if (!abortController) return;
    abortController.abort();
    abortController = null;
    setCancelled();
  };

  const start = (file: File, elf: ElfParseResult): void => {
    cancel();
    setDisassemblyUiRunning(true);
    const localRunId = ++runId;
    const localAbortController = new AbortController();
    abortController = localAbortController;

    updateElfDisassemblyProgress({
      stage: "loading",
      bytesSampled: 1,
      bytesDecoded: 0,
      instructionCount: 0,
      invalidInstructionCount: 0
    });

    void (async () => {
      const report = await analyze(file, {
        machine: elf.header.machine,
        is64Bit: elf.is64,
        littleEndian: elf.littleEndian,
        entrypointVaddr: elf.header.entry,
        programHeaders: elf.programHeaders,
        sections: elf.sections,
        yieldEveryInstructions: 1024,
        signal: localAbortController.signal,
        onProgress: progress => {
          if (localRunId !== runId) return;
          updateElfDisassemblyProgress(progress);
        }
      });

      if (localRunId !== runId) return;
      if (localAbortController.signal.aborted) return;
      if (opts.getCurrentFile() !== file) return;

      const current = opts.getCurrentParseResult();
      if (current.analyzer !== "elf" || !current.parsed) return;
      current.parsed.disassembly = report;
      setDisassemblyUiRunning(false);
      abortController = null;
      opts.renderResult(current);
    })();
  };

  return { cancel, start };
};

