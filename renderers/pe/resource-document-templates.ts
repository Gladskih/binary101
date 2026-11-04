import type { ResourcePreviewWithIssues } from "../../analyzers/pe/resources/preview/types.js";
import { readMfcDocumentTemplate } from "../../analyzers/pe/resources/preview/mfc-document-template.js";
import { escapeHtmlText } from "../../html-utils.js";

export const renderResourceDocumentTemplates = (leaf: ResourcePreviewWithIssues): string => {
  const rows: string[] = [];
  for (const string of leaf.stringTable ?? []) {
    const template = readMfcDocumentTemplate(string.text);
    if (!template) continue;
    for (const [name, value] of Object.entries(template)) rows.push(`<tr><td>${string.id ?? "—"}</td>` +
      `<th scope="row">${name}</th><td>${escapeHtmlText(value)}</td></tr>`);
  }
  return rows.length ? `<details><summary>Possible MFC document templates</summary>` +
    `<p class="smallNote">Recognized by the CDocTemplate string convention; runtime use is unconfirmed.</p>` +
    `<table class="table"><thead><tr><th>String ID</th><th>Field</th><th>Value</th></tr></thead>` +
    `<tbody>${rows.join("")}</tbody></table></details>` : "";
};
