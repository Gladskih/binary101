import { formatHumanSize } from "../binary-utils.js";
import { createFileRangeReader, type FileRangeReader } from "../analyzers/file-range-reader.js";
import type { ParseForUiResult } from "../analyzers/index.js";
import { isPeWindowsParseResult, type PeParseResult } from "../analyzers/pe/index.js";
import {
  analyzePeInstructionSets,
  type AnalyzePeInstructionSetOptions,
  type PeInstructionSetProgress,
  type PeInstructionSetReport
} from "../analyzers/pe/disassembly/index.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../analyzers/pe/optional-header/magic.js";
import { collectPeDisassemblySeeds } from "./pe-disassembly-seeds.js";

type AnalyzePeInstructionSets = (
  reader: FileRangeReader,
  opts: AnalyzePeInstructionSetOptions
) => Promise<PeInstructionSetReport>;

type PeDisassemblyControllerOptions = {
  getCurrentFile: () => File | null;
  getCurrentParseResult: () => ParseForUiResult;
  renderResult: (result: ParseForUiResult) => void;
  analyze?: AnalyzePeInstructionSets;
};

export type PeDisassemblyController = {
  cancel: () => void;
  start: (file: File, pe: PeParseResult) => void;
};

const ANALYZE_BUTTON_ID = "peInstructionSetsAnalyzeButton";
const CANCEL_BUTTON_ID = "peInstructionSetsCancelButton";
const PROGRESS_TEXT_ID = "peInstructionSetsProgressText";
const PROGRESS_BAR_ID = "peInstructionSetsProgress";
const CHIP_ID_PREFIX = "peInstructionSetChip_";
const COUNT_ID_PREFIX = "peInstructionSetCount_";

const setDisassemblyUiState = (state: "busy" | "idle"): void => {
  const isBusy = state === "busy";
  const button = document.getElementById(ANALYZE_BUTTON_ID);
  if (button && "disabled" in button) (button as HTMLButtonElement).disabled = isBusy;

  const cancelButton = document.getElementById(CANCEL_BUTTON_ID);
  if (cancelButton && "hidden" in cancelButton) {
    (cancelButton as HTMLElement).hidden = !isBusy;
  }

  const bar = document.getElementById(PROGRESS_BAR_ID);
  if (bar instanceof HTMLProgressElement) {
    bar.hidden = !isBusy;
  }
};

const updatePeDisassemblyProgress = (progress: PeInstructionSetProgress): void => {
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
    text.textContent =
      `${stageLabel} ${percent}% (${bytesText}), ${progress.instructionCount} instr., ` +
      `${progress.invalidInstructionCount} invalid.`;
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
  setDisassemblyUiState("idle");
  const progressText = document.getElementById(PROGRESS_TEXT_ID);
  if (progressText instanceof HTMLElement) {
    progressText.textContent = "Cancelled.";
  }
};

export const createPeDisassemblyController = (
  opts: PeDisassemblyControllerOptions
): PeDisassemblyController => {
  let abortController: AbortController | null = null;
  let runId = 0;
  const analyze = opts.analyze ?? analyzePeInstructionSets;

  const cancel = (): void => {
    runId++;
    if (!abortController) return;
    abortController.abort();
    abortController = null;
    setCancelled();
  };

  const start = (file: File, pe: PeParseResult): void => {
    cancel();
    setDisassemblyUiState("busy");
    const localRunId = ++runId;
    const localAbortController = new AbortController();
    abortController = localAbortController;

    updatePeDisassemblyProgress({
      stage: "loading",
      bytesSampled: 1,
      bytesDecoded: 0,
      instructionCount: 0,
      invalidInstructionCount: 0
    });

    void (async () => {
      const reader = createFileRangeReader(file, 0, file.size);
      const windowsPe = isPeWindowsParseResult(pe) ? pe : null;
      const windowsOpt = windowsPe?.opt ?? null;
      const seeds = await collectPeDisassemblySeeds(file, pe);

      const report = await analyze(reader, {
        coffMachine: seeds.canonicalMachine,
        is64Bit: windowsOpt?.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC,
        imageBase: windowsOpt?.ImageBase ?? 0n,
        entrypointRva: seeds.entrypointRva,
        exportRvas: seeds.exportRvas,
        unwindBeginRvas: seeds.unwindBeginRvas,
        unwindHandlerRvas: seeds.unwindHandlerRvas,
        guardCFFunctionRvas: seeds.guardCFFunctionRvas,
        safeSehHandlerRvas: seeds.safeSehHandlerRvas,
        tlsCallbackRvas: seeds.tlsCallbackRvas,
        ...(seeds.extraEntrypoints.length ? { extraEntrypoints: seeds.extraEntrypoints } : {}),
        ...(windowsOpt ? { headerRvaLimit: windowsOpt.SizeOfHeaders } : {}),
        rvaToOff: pe.rvaToOff,
        sections: pe.sections,
        yieldEveryInstructions: 1024,
        signal: localAbortController.signal,
        onProgress: progress => {
          if (localRunId !== runId) return;
          updatePeDisassemblyProgress(progress);
        }
      });

      if (localRunId !== runId) return;
      if (localAbortController.signal.aborted) return;
      if (opts.getCurrentFile() !== file) return;

      const current = opts.getCurrentParseResult();
      if (
        current.analyzer !== "pe" ||
        !current.parsed ||
        !isPeWindowsParseResult(current.parsed)
      ) {
        return;
      }
      current.parsed.disassembly = report;
      setDisassemblyUiState("idle");
      abortController = null;
      opts.renderResult(current);
    })();
  };

  return { cancel, start };
};
