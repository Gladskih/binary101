import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import { analyzePeSanitizers } from "../../analyzers/pe/sanitizers.js";
import { renderSanitizerEvidence } from "../sanitizer-evidence.js";
import { renderPeSectionStart, renderPeSectionEnd } from "./collapsible-section.js";

export const renderPeSanitizers = (pe: PeWindowsParseResult): string =>
  renderPeSectionStart("Sanitizer evidence") +
  renderSanitizerEvidence(analyzePeSanitizers(pe)) + renderPeSectionEnd();
