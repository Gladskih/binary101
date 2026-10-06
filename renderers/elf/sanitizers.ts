import type { ElfParseResult } from "../../analyzers/elf/types.js";
import { analyzeElfSanitizers } from "../../analyzers/elf/sanitizers.js";
import { renderSanitizerEvidence } from "../sanitizer-evidence.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";

export const renderElfSanitizers = (elf: ElfParseResult, out: string[]): void => {
  out.push(renderElfSectionStart("Sanitizer evidence"));
  out.push(renderSanitizerEvidence(analyzeElfSanitizers(elf)));
  out.push(renderElfSectionEnd());
};
