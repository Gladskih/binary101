"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";

export interface Fb2Languages {
  lang?: string | null;
  srcLang?: string | null;
}

export interface Fb2Sequence {
  name?: string | null;
  number?: string | number | null;
}

export interface Fb2DocumentInfo {
  authors?: string[];
  programUsed?: string | null;
  documentId?: string | null;
  documentVersion?: string | null;
  documentDate?: string | null;
  sourceUrls?: string[];
  sourceOcr?: string | null;
}

export interface Fb2PublishInfo {
  publisher?: string | null;
  city?: string | null;
  year?: string | null;
  isbn?: string | null;
}

export function renderList(items: string[] | null | undefined): string {
  if (!items || !items.length) return "";
  return `<ul>${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

export function renderLanguages(languages: Fb2Languages | null | undefined): string {
  if (!languages) return "Unknown";
  const parts = [];
  if (languages.lang) parts.push(`Primary: ${escapeHtml(languages.lang)}`);
  if (languages.srcLang) parts.push(`Source: ${escapeHtml(languages.srcLang)}`);
  return parts.length ? parts.join("; ") : "Unknown";
}

export function renderSequence(sequence: Fb2Sequence | null | undefined): string {
  if (!sequence) return "Not specified";
  const { name, number } = sequence;
  if (name && number) return `${escapeHtml(name)} (#${escapeHtml(number)})`;
  if (name) return escapeHtml(name);
  if (number) return `#${escapeHtml(number)}`;
  return "Not specified";
}

export function renderDocumentInfo(info: Fb2DocumentInfo | null | undefined): string {
  if (!info) return "";
  const out = [];
  out.push("<h4>Document info</h4><dl>");
  out.push(
    renderDefinitionRow(
      "Document authors",
      info.authors && info.authors.length
        ? renderList(info.authors)
        : "Not provided",
      "Author tags inside <document-info>; often different from the title's authors " +
        "when converters add their own credit."
    )
  );
  out.push(
    renderDefinitionRow(
      "Program used",
      escapeHtml(info.programUsed || "Not provided"),
      "Software name recorded by the creator/converter."
    )
  );
  out.push(
    renderDefinitionRow(
      "Document ID",
      escapeHtml(info.documentId || "Not provided"),
      "Identifier from <id>; usually a UUID or hash."
    )
  );
  out.push(
    renderDefinitionRow(
      "Version",
      escapeHtml(info.documentVersion || "Not provided"),
      "Version field from <version>; increments when metadata changes."
    )
  );
  out.push(
    renderDefinitionRow(
      "Creation date",
      escapeHtml(info.documentDate || "Not provided"),
      "Date from <date>; may include both text and a value attribute."
    )
  );
  out.push(
    renderDefinitionRow(
      "Source URLs",
      info.sourceUrls && info.sourceUrls.length
        ? renderList(info.sourceUrls)
        : "Not provided",
      "<src-url> links back to the original publication."
    )
  );
  out.push(
    renderDefinitionRow(
      "Source OCR",
      escapeHtml(info.sourceOcr || "Not provided"),
      "Recorded OCR software when the book was digitized."
    )
  );
  out.push("</dl>");
  return out.join("");
}

export function renderPublishInfo(publishInfo: Fb2PublishInfo | null | undefined): string {
  if (!publishInfo) return "";
  const out = [];
  out.push("<h4>Publication info</h4><dl>");
  out.push(
    renderDefinitionRow(
      "Publisher",
      escapeHtml(publishInfo.publisher || "Not provided"),
      "Publisher from <publish-info>."
    )
  );
  out.push(
    renderDefinitionRow(
      "City",
      escapeHtml(publishInfo.city || "Not provided"),
      "City of publication if supplied."
    )
  );
  out.push(
    renderDefinitionRow(
      "Year",
      escapeHtml(publishInfo.year || "Not provided"),
      "Publication year (free-form in FB2)."
    )
  );
  out.push(
    renderDefinitionRow(
      "ISBN",
      escapeHtml(publishInfo.isbn || "Not provided"),
      "ISBN from <isbn>; may be absent for drafts."
    )
  );
  out.push("</dl>");
  return out.join("");
}

export function renderIssues(issues: string[] | null | undefined): string {
  if (!issues || issues.length === 0) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
}
