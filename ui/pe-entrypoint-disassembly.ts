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
  renderResult: (result: ParseForUiResult) => void;
  analyze?: AnalyzePeEntrypointDisassembly;
};

export type PeEntrypointDisassemblyController = {
  cancel: () => void;
  start: (file: File, pe: PeParseResult) => void;
};

const ENTRYPOINT_BUTTON_ID = "peEntrypointDisassembleButton";

const setEntrypointUiState = (state: "busy" | "idle"): void => {
  const isBusy = state === "busy";
  const button = document.getElementById(ENTRYPOINT_BUTTON_ID);
  if (button && "disabled" in button) {
    (button as HTMLButtonElement).disabled = isBusy;
  }
};

const buildFailureReport = (
  pe: PeWindowsParseResult,
  message: string
): PeEntrypointDisassemblyReport => ({
  bitness: pe.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 64 : 32,
  entrypointRva: pe.opt.AddressOfEntryPoint >>> 0,
  bytesDecoded: 0,
  instructionCount: 0,
  blocks: [],
  issues: [message]
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

  const start = (file: File, pe: PeParseResult): void => {
    cancel();
    setEntrypointUiState("busy");
    const localRunId = ++runId;
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
          coffMachine: getCanonicalPeMachine(windowsPe.coff.Machine),
          is64Bit: windowsPe.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC,
          imageBase: windowsPe.opt.ImageBase,
          entrypointRva: windowsPe.opt.AddressOfEntryPoint,
          headerRvaLimit: windowsPe.opt.SizeOfHeaders,
          imports: windowsPe.imports,
          delayImports: windowsPe.delayImports,
          loadcfg: windowsPe.loadcfg,
          rvaToOff: windowsPe.rvaToOff,
          sections: windowsPe.sections
        }
      ).catch(error => buildFailureReport(windowsPe, `Entrypoint disassembly failed (${String(error)})`));
      if (localRunId !== runId) return;
      setEntrypointUiState("idle");
      if (opts.getCurrentFile() !== file) return;
      const current = opts.getCurrentParseResult();
      if (current.analyzer !== "pe" || !current.parsed || !isPeWindowsParseResult(current.parsed)) return;
      current.parsed.entrypointDisassembly = report;
      opts.renderResult(current);
    })();
  };

  return { cancel, start };
};
