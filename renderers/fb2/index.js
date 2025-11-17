"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";

function renderList(items) {
  if (!items || !items.length) return "";
  return `<ul>${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function renderLanguages(languages) {
  if (!languages) return "Unknown";
  const parts = [];
  if (languages.lang) parts.push(`Primary: ${escapeHtml(languages.lang)}`);
  if (languages.srcLang) parts.push(`Source: ${escapeHtml(languages.srcLang)}`);
  return parts.length ? parts.join("; ") : "Unknown";
}

function renderSequence(sequence) {
  if (!sequence) return "Not specified";
  const { name, number } = sequence;
  if (name && number) return `${escapeHtml(name)} (#${escapeHtml(number)})`;
  if (name) return escapeHtml(name);
  if (number) return `#${escapeHtml(number)}`;
  return "Not specified";
}

function renderDocumentInfo(info) {
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

function renderPublishInfo(publishInfo) {
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

export function renderFb2(fb2) {
  if (!fb2) return "";
  const {
    size,
    bytesInspected,
    parseError,
    title,
    genres,
    keywords,
    languages,
    annotation,
    sequence,
    coverImage,
    titleAuthors,
    bodyCount,
    sectionCount,
    binaryCount,
    documentInfo,
    publishInfo
  } = fb2;

  const out = [];
  out.push("<h3>FictionBook 2.0 (FB2) metadata</h3><dl>");
  out.push(
    renderDefinitionRow(
      "File size",
      escapeHtml(formatHumanSize(size)),
      "Total size of the FB2 container as provided by the browser."
    )
  );
  out.push(
    renderDefinitionRow(
      "Bytes inspected",
      escapeHtml(formatHumanSize(bytesInspected)),
      "Parser reads only the opening portion where FB2 metadata resides."
    )
  );
  out.push(
    renderDefinitionRow(
      "XML parse status",
      parseError ? "Parser reported errors" : "Parsed without errors",
      "DOMParser diagnostics for the inspected slice; errors suggest malformed XML."
    )
  );
  out.push(
    renderDefinitionRow(
      "Title",
      escapeHtml(title || "Not provided"),
      "<book-title> from <title-info>."
    )
  );
  out.push(
    renderDefinitionRow(
      "Authors",
      titleAuthors && titleAuthors.length
        ? renderList(titleAuthors)
        : "Not provided",
      "Author list from <title-info>."
    )
  );
  out.push(
    renderDefinitionRow(
      "Genres",
      genres && genres.length ? renderList(genres) : "Not provided",
      "<genre> tags hint at subject classification."
    )
  );
  out.push(
    renderDefinitionRow(
      "Languages",
      renderLanguages(languages),
      "Primary and optional source language from <lang> and <src-lang>."
    )
  );
  out.push(
    renderDefinitionRow(
      "Series / sequence",
      renderSequence(sequence),
      "Name/number from the first <sequence> under <title-info>."
    )
  );
  out.push(
    renderDefinitionRow(
      "Keywords",
      keywords && keywords.length ? renderList(keywords) : "Not provided",
      "Keywords field under <title-info>."
    )
  );
  out.push(
    renderDefinitionRow(
      "Annotation",
      annotation ? escapeHtml(annotation) : "Not provided",
      "Short description from <annotation>; trimmed to the first few hundred characters."
    )
  );
  out.push(
    renderDefinitionRow(
      "Cover image reference",
      coverImage ? escapeHtml(coverImage) : "Not provided",
      "Href attribute of <coverpage><image>; may refer to an embedded <binary> or external link."
    )
  );
  out.push(
    renderDefinitionRow(
      "Structure",
      `${bodyCount} bodies, ${sectionCount} sections`,
      "Counts of <body> and nested <section> elements."
    )
  );
  out.push(
    renderDefinitionRow(
      "Embedded binaries",
      `${binaryCount} <binary> elements`,
      "Number of <binary> payloads (images or other data)."
    )
  );
  out.push("</dl>");

  out.push(renderDocumentInfo(documentInfo));
  out.push(renderPublishInfo(publishInfo));

  return out.join("");
}
