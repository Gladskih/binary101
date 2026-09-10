import { escapeHtml } from "../../html-utils.js";
import { evaluateElfCfi } from "../../analyzers/elf/cfi-state.js";
import type { ElfCfaRule, ElfCfiRegisterRule } from "../../analyzers/elf/cfi-state-types.js";
import type { ElfUnwindCie, ElfUnwindFde } from "../../analyzers/elf/unwind-types.js";

const cfaText = (cfa: ElfCfaRule): string => {
  if (!cfa) return "Unspecified";
  return "expression" in cfa ? `Expression: ${cfa.expression}` : `r${cfa.register} + (${cfa.offset})`;
};
const registerText = (rule: ElfCfiRegisterRule): string => {
  if ("offset" in rule) return `${rule.kind}: CFA + (${rule.offset})`;
  if ("expression" in rule) return `${rule.kind}: ${rule.expression}`;
  if ("register" in rule) return `r${rule.register}`;
  return rule.kind;
};

export const renderElfCfiState = (cie: ElfUnwindCie, fde: ElfUnwindFde): string => {
  const evaluation = evaluateElfCfi(cie, fde);
  const rows = evaluation.rows.map(row => `<tr><td class="peNumeric">0x${row.location.toString(16)}</td>` +
    `<td>${escapeHtml(cfaText(row.cfa))}</td><td>${escapeHtml(Object.entries(row.registers)
      .map(([register, rule]) => `r${register}: ${registerText(rule)}`).join("; "))}</td>` +
    `<td>${row.returnAddressSigned ? "Signed" : "Unsigned"}</td>` +
    `<td class="peNumeric">${row.argumentSize}</td></tr>`).join("");
  const issues = evaluation.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<details><summary>${evaluation.rows.length} unwind rule rows</summary>` +
    `<div class="tableWrap"><table class="table"><thead><tr><th>PC start</th><th>CFA</th>` +
    `<th>Register rules</th><th>Return address</th><th>Argument bytes</th></tr></thead>` +
    `<tbody>${rows}</tbody></table></div>${issues ? `<ul>${issues}</ul>` : ""}</details>`;
};
