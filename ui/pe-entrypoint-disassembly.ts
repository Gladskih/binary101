import { formatHumanSize } from "../binary-utils.js";
import { handlePeSpecialInstructionClick } from "./pe-special-instructions.js";
import { createFileRangeReader, type FileRangeReader } from "../analyzers/file-range-reader.js";
import type { ParseForUiResult } from "../analyzers/index.js";
import {
  isPeWindowsParseResult,
  type PeParseResult,
  type PeWindowsParseResult
} from "../analyzers/pe/index.js";
import { getCanonicalPeMachine } from "../analyzers/pe/machine.js";
import {
  analyzePeEntrypointDisassembly,
  type AnalyzePeEntrypointDisassemblyOptions,
  type PeEntrypointDisassemblyProgress,
  type PeEntrypointDisassemblyReport
} from "../analyzers/pe/disassembly/index.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../analyzers/pe/optional-header/magic.js";

type AnalyzePeEntrypointDisassembly = (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions
) => Promise<PeEntrypointDisassemblyReport>;

type PeEntrypointDisassemblyControllerOptions = {
  getCurrentFile: () => File | null;
  getCurrentParseResult: () => ParseForUiResult;
  renderPanel?: (pe: PeWindowsParseResult) => void;
  renderResult?: (result: ParseForUiResult) => void;
  analyze?: AnalyzePeEntrypointDisassembly;
};

export type PeEntrypointDisassemblyController = {
  cancel: () => void;
  start: (file: File, pe: PeParseResult, requestedRva?: number) => void;
  handleClick: (target: Element | null) => boolean;
};

const ENTRYPOINT_BUTTON_ID = "peEntrypointDisassembleButton";
const PROGRESS_STAGE_ID = "peEntrypointDisassemblyProgressStage";
const PROGRESS_DECODED_ID = "peEntrypointDisassemblyProgressDecoded";
const PROGRESS_BYTES_ID = "peEntrypointDisassemblyProgressBytes";
const PROGRESS_QUEUED_ID = "peEntrypointDisassemblyProgressQueued";

const setEntrypointUiState = (state: "busy" | "idle"): void => {
  const isBusy = state === "busy";
  const button = document.getElementById(ENTRYPOINT_BUTTON_ID);
  if (button && "disabled" in button) {
    (button as HTMLButtonElement).disabled = isBusy;
  }
};

const updateEntrypointProgress = (progress: PeEntrypointDisassemblyProgress): void => {
  const stage = document.getElementById(PROGRESS_STAGE_ID);
  const decoded = document.getElementById(PROGRESS_DECODED_ID);
  const bytes = document.getElementById(PROGRESS_BYTES_ID);
  const queued = document.getElementById(PROGRESS_QUEUED_ID);
  const stageLabel =
    progress.stage === "loading"
      ? "Loading disassembler..."
      : progress.stage === "decoding"
        ? "Disassembling..."
        : "Done.";
  if (stage instanceof HTMLElement) stage.textContent = stageLabel;
  if (decoded instanceof HTMLElement) {
    decoded.textContent = `Instructions decoded: ${progress.instructionCount}`;
  }
  if (bytes instanceof HTMLElement) {
    bytes.textContent = `Bytes decoded: ${formatHumanSize(progress.bytesDecoded)}`;
  }
  if (queued instanceof HTMLElement) {
    queued.textContent = `Queued targets: ${progress.pendingBlockCount}`;
  }
};

const buildFailureReport = (
  pe: PeWindowsParseResult,
  message: string,
  requestedRva?: number
): PeEntrypointDisassemblyReport => ({
  bitness: pe.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 64 : 32,
  entrypointRva: requestedRva ?? (pe.opt.AddressOfEntryPoint >>> 0),
  bytesDecoded: 0,
  instructionCount: 0,
  blocks: [],
  issues: [message]
});

const disassemblyOptions = (
  pe: PeWindowsParseResult, requestedRva: number | undefined
): AnalyzePeEntrypointDisassemblyOptions => ({
  coffMachine: getCanonicalPeMachine(pe.coff.Machine),
  is64Bit: pe.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC,
  imageBase: pe.opt.ImageBase,
  entrypointRva: requestedRva ?? pe.opt.AddressOfEntryPoint,
  headerRvaLimit: pe.opt.SizeOfHeaders,
  imports: pe.imports,
  delayImports: pe.delayImports,
  loadcfg: pe.loadcfg,
  rvaToOff: pe.rvaToOff,
  sections: pe.sections,
  yieldEveryInstructions: 64
});

export const createPeEntrypointDisassemblyController = (
  opts: PeEntrypointDisassemblyControllerOptions
): PeEntrypointDisassemblyController => {
  let runId = 0;
  const analyze = opts.analyze ?? analyzePeEntrypointDisassembly;

  const cancel = (): void => {
    runId += 1;
    setEntrypointUiState("idle");
  };

  const start = (file: File, pe: PeParseResult, requestedRva?: number): void => {
    cancel();
    setEntrypointUiState("busy");
    const localRunId = ++runId;
    updateEntrypointProgress({
      stage: "loading",
      bytesDecoded: 0,
      instructionCount: 0,
      pendingBlockCount: 0
    });
    void (async () => {
      const windowsPe = isPeWindowsParseResult(pe) ? pe : null;
      if (!windowsPe) {
        if (localRunId === runId) setEntrypointUiState("idle");
        return;
      }
      const reader = createFileRangeReader(file, 0, file.size);
      const report = await analyze(
        reader,
        {
          ...disassemblyOptions(windowsPe, requestedRva),
          onProgress: progress => {
            if (localRunId === runId) updateEntrypointProgress(progress);
          }
        }
      ).catch(error => buildFailureReport(
        windowsPe, `Entrypoint disassembly failed (${String(error)})`, requestedRva
      ));
      if (localRunId !== runId) return;
      setEntrypointUiState("idle");
      if (opts.getCurrentFile() !== file) return;
      const current = opts.getCurrentParseResult();
      if (current.analyzer !== "pe" || !current.parsed || !isPeWindowsParseResult(current.parsed)) return;
      current.parsed.entrypointDisassembly = report;
      if (opts.renderPanel) {
        opts.renderPanel(current.parsed);
      } else {
        opts.renderResult?.(current);
      }
      if (requestedRva != null) revealSelectedDisassembly();
    })();
  };

  return {
    cancel, start,
    handleClick: target => handlePeSpecialInstructionClick(
      target, opts.getCurrentFile(), opts.getCurrentParseResult(), { start }
    )
  };
};

const revealSelectedDisassembly = (): void => {
  const panel = document.getElementById("peEntrypointDisassemblyPanel");
  const details = panel?.querySelector("details");
  if (!details || !(details instanceof HTMLDetailsElement)) return;
  details.open = true;
  const summary = details.querySelector("summary");
  summary?.focus({ preventScroll: true });
  summary?.scrollIntoView({ block: "start" });
};
