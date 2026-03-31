"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";
import {
  renderDocumentInfo,
  renderIssues,
  renderLanguages,
  renderList,
  renderPublishInfo,
  renderSequence,
  type Fb2DocumentInfo,
  type Fb2Languages,
  type Fb2PublishInfo,
  type Fb2Sequence
} from "./metadata-sections.js";

interface Fb2ParseResult {
  size: number;
  bytesInspected?: number | null;
  parseError?: boolean | null;
  issues?: string[] | null;
  title?: string | null;
  genres?: string[] | null;
  keywords?: string[] | null;
  languages?: Fb2Languages | null;
  annotation?: string | null;
  sequence?: Fb2Sequence | null;
  coverImage?: string | null;
  titleAuthors?: string[] | null;
  bodyCount?: number | null;
  sectionCount?: number | null;
  binaryCount?: number | null;
  documentInfo?: Fb2DocumentInfo | null;
  publishInfo?: Fb2PublishInfo | null;
  embeddedBinaryWarnings?: string[] | null;
}

export function renderFb2(fb2: Fb2ParseResult | null | unknown): string {
  const data = fb2 as Fb2ParseResult | null;
  if (!data) return "";
  const {
    size,
    bytesInspected,
    parseError,
    issues,
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
  } = data;

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
      bytesInspected != null
        ? escapeHtml(formatHumanSize(bytesInspected))
        : "Unknown",
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

  out.push(renderIssues(issues));
  out.push(renderDocumentInfo(documentInfo));
  out.push(renderPublishInfo(publishInfo));

  return out.join("");
}
