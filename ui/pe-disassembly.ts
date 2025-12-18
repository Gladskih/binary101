import { formatHumanSize } from "../binary-utils.js";
import type { ParseForUiResult } from "../analyzers/index.js";
import type { PeParseResult } from "../analyzers/pe/index.js";
import {
  analyzePeInstructionSets,
  type AnalyzePeInstructionSetOptions,
  type PeInstructionSetProgress,
  type PeInstructionSetReport
} from "../analyzers/pe/disassembly.js";
import {
  readGuardCFFunctionTableRvas,
  readGuardEhContinuationTableRvas,
  readGuardLongJumpTargetTableRvas,
  readLoadConfigPointerRva,
  readSafeSehHandlerTableRvas
} from "../analyzers/pe/load-config.js";

const IMAGE_FILE_MACHINE_I386 = 0x014c;

type AnalyzePeInstructionSets = (
  file: File,
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
    setDisassemblyUiRunning(true);
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
      const exportRvas =
        pe.exports?.entries
          ?.filter(entry => entry.rva && !entry.forwarder)
          .map(entry => entry.rva >>> 0) ?? [];

      const unwindBeginRvas =
        pe.opt.isPlus && Array.isArray(pe.exception?.beginRvas)
          ? pe.exception.beginRvas
              .filter(rva => Number.isSafeInteger(rva) && rva > 0)
              .map(rva => rva >>> 0)
          : [];

      const unwindHandlerRvas =
        pe.opt.isPlus && Array.isArray(pe.exception?.handlerRvas)
          ? pe.exception.handlerRvas
              .filter(rva => Number.isSafeInteger(rva) && rva > 0)
              .map(rva => rva >>> 0)
          : [];

      const tlsCallbackRvas = Array.isArray(pe.tls?.CallbackRvas)
        ? pe.tls.CallbackRvas.filter(rva => Number.isSafeInteger(rva) && rva > 0).map(rva => rva >>> 0)
        : [];

      const guardCFFunctionRvas = pe.loadcfg
        ? await readGuardCFFunctionTableRvas(
            file,
            pe.rvaToOff,
            pe.opt.ImageBase,
            pe.loadcfg.GuardCFFunctionTable,
            pe.loadcfg.GuardCFFunctionCount
          ).catch(() => [])
        : [];

      const safeSehHandlerRvas =
        pe.coff.Machine === IMAGE_FILE_MACHINE_I386 && !pe.opt.isPlus && pe.loadcfg
          ? await readSafeSehHandlerTableRvas(
              file,
              pe.rvaToOff,
              pe.opt.ImageBase,
              pe.loadcfg.SEHandlerTable,
              pe.loadcfg.SEHandlerCount
            ).catch(() => [])
          : [];

      const extraEntrypoints: Array<{ source: string; rvas: number[] }> = [];
      const addPointerSeed = (source: string, pointerVa: number | undefined): void => {
        if (!Number.isSafeInteger(pe.opt.ImageBase)) return;
        const rva = readLoadConfigPointerRva(pe.opt.ImageBase, pointerVa ?? 0);
        if (rva == null) return;
        extraEntrypoints.push({ source, rvas: [rva] });
      };

      if (pe.loadcfg) {
        addPointerSeed("GuardCF check function", pe.loadcfg.GuardCFCheckFunctionPointer);
        addPointerSeed("GuardCF dispatch function", pe.loadcfg.GuardCFDispatchFunctionPointer);
        addPointerSeed("GuardXFG check function", pe.loadcfg.GuardXFGCheckFunctionPointer);
        addPointerSeed("GuardXFG dispatch function", pe.loadcfg.GuardXFGDispatchFunctionPointer);
        addPointerSeed("GuardXFG table dispatch function", pe.loadcfg.GuardXFGTableDispatchFunctionPointer);
        addPointerSeed("Guard memcpy function", pe.loadcfg.GuardMemcpyFunctionPointer);
      }

      const guardEhContinuationRvas = pe.loadcfg
        ? await readGuardEhContinuationTableRvas(
            file,
            pe.rvaToOff,
            pe.opt.ImageBase,
            pe.loadcfg.GuardEHContinuationTable,
            pe.loadcfg.GuardEHContinuationCount
          ).catch(() => [])
        : [];
      if (guardEhContinuationRvas.length) {
        extraEntrypoints.push({ source: "GuardEH continuation", rvas: guardEhContinuationRvas });
      }

      const guardLongJumpTargetRvas = pe.loadcfg
        ? await readGuardLongJumpTargetTableRvas(
            file,
            pe.rvaToOff,
            pe.opt.ImageBase,
            pe.loadcfg.GuardLongJumpTargetTable,
            pe.loadcfg.GuardLongJumpTargetCount
          ).catch(() => [])
        : [];
      if (guardLongJumpTargetRvas.length) {
        extraEntrypoints.push({ source: "Guard longjmp target", rvas: guardLongJumpTargetRvas });
      }

      const report = await analyze(file, {
        coffMachine: pe.coff.Machine,
        is64Bit: pe.opt.isPlus,
        imageBase: pe.opt.ImageBase,
        entrypointRva: pe.opt.AddressOfEntryPoint,
        exportRvas,
        unwindBeginRvas,
        unwindHandlerRvas,
        guardCFFunctionRvas,
        safeSehHandlerRvas,
        tlsCallbackRvas,
        ...(extraEntrypoints.length ? { extraEntrypoints } : {}),
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
      if (current.analyzer !== "pe" || !current.parsed) return;
      current.parsed.disassembly = report;
      setDisassemblyUiRunning(false);
      abortController = null;
      opts.renderResult(current);
    })();
  };

  return { cancel, start };
};
