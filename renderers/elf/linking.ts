import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";
import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import { renderElfDynamicEntries, renderElfDynamicTagCoverage } from "./dynamic-entries.js";
import type {
  ElfDynamicInfo,
  ElfInterpreterInfo,
  ElfParseResult
} from "../../analyzers/elf/types.js";
import { renderCountedCollection } from "../counted-collection.js";
import { elfDynamicTagCatalog } from "../../analyzers/elf/dynamic-tags.js";

const collectIssues = (interpreter?: ElfInterpreterInfo, dynamic?: ElfDynamicInfo): string[] => {
  const issues: string[] = [];
  interpreter?.issues?.forEach(issue => issues.push(`PT_INTERP: ${issue}`));
  dynamic?.issues?.forEach(issue => issues.push(`Dynamic: ${issue}`));
  return issues;
};

export function renderElfLinking(elf: ElfParseResult, out: string[]): void {
  const interpreter = elf.interpreter;
  const dynamic = elf.dynamic;
  if (!interpreter && !dynamic) return;
  out.push(renderElfSectionStart(`Dynamic linking`));
  out.push(
    `<div class="smallNote">Interpreter and DT_* tags describe how the dynamic loader resolves shared libraries and startup routines.</div>`
  );
  out.push(`<dl>`);
  if (interpreter) {
    out.push(renderDefinitionRow("Interpreter (PT_INTERP)",
      interpreter.path ? `<span class="mono">${escapeHtml(interpreter.path)}</span>` : "-"));
  }
  out.push(`</dl>`);
  if (dynamic) {
    const catalog = elfDynamicTagCatalog(elf.header.machine);
    out.push(renderElfDynamicEntries(dynamic.entries, catalog), renderElfDynamicTagCoverage(dynamic, catalog));
  }
  const issues = collectIssues(interpreter, dynamic);
  if (issues.length) {
    out.push(renderCountedCollection("Notes",
      `<ul>${issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`, issues.length));
  }
  out.push(renderElfSectionEnd());
}
