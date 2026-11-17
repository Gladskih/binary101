import type { ParseForUiResult } from "../analyzers/index.js";
import { isPeWindowsParseResult } from "../analyzers/pe/index.js";
import type { PeEntrypointDisassemblyController } from "./pe-entrypoint-disassembly.js";

export const handlePeSpecialInstructionClick = (
  target: Element | null,
  file: File | null,
  result: ParseForUiResult,
  controller: Pick<PeEntrypointDisassemblyController, "start">
): boolean => {
  const button = target?.closest("[data-pe-special-rva]");
  if (!(button instanceof HTMLElement)) return false;
  if (!file || result.analyzer !== "pe" || !result.parsed) return true;
  if (!isPeWindowsParseResult(result.parsed)) return true;
  const rva = Number(button.dataset["peSpecialRva"]);
  // Only navigate to sites recorded by an analysis of the current file.
  if (!result.parsed.disassembly?.specialInstructions.some(
    finding => finding.sampleRvas.includes(rva)
  ) && !result.parsed.exception?.prologValidation?.findings.some(
    finding => finding.beginRva === rva
  )) return true;
  controller.start(file, result.parsed, rva);
  return true;
};
