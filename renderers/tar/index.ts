"use strict";

import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";
import type { TarEntry, TarParseResult } from "../../analyzers/tar/index.js";

const formatSize = (value: number | null | undefined): string => {
  if (value == null) return "-";
  if (!Number.isFinite(value)) return `${value} bytes`;
  return formatHumanSize(value);
};

const formatCount = (value: number | null | undefined): string =>
  value == null ? "-" : value.toString();

const formatMode = (entry: TarEntry): string => {
  if (entry.modeSymbolic && entry.modeOctal) {
    return `${escapeHtml(entry.modeSymbolic)} (${escapeHtml(entry.modeOctal)})`;
  }
  if (entry.modeOctal) return escapeHtml(entry.modeOctal);
  if (entry.modeSymbolic) return escapeHtml(entry.modeSymbolic);
  return "-";
};

const describeType = (entry: TarEntry): string => {
  const label = entry.typeLabel || "Entry";
  const code = entry.typeFlag || "";
  return code ? `${escapeHtml(label)} <span class="dim">(${escapeHtml(code)})</span>` : escapeHtml(label);
};

const describeNotes = (entry: TarEntry): string => {
  const notes: string[] = [];
  if (entry.linkName) notes.push(`→ ${entry.linkName}`);
  if (entry.usesLongName) notes.push("GNU long name");
  if (entry.usesLongLink) notes.push("GNU long link");
  if (entry.usedPaxPath) notes.push("PAX path");
  if (entry.hasPax && entry.paxKeys) {
    notes.push(`PAX: ${entry.paxKeys.join(", ")}`);
  }
  if (entry.checksumValid === false) notes.push("Checksum mismatch");
  return notes.length ? escapeHtml(notes.join("; ")) : "-";
};

const describeOwner = (entry: TarEntry): string => {
  const owner = entry.uname || (entry.uid != null ? entry.uid.toString() : "-");
  const group = entry.gname || (entry.gid != null ? entry.gid.toString() : "-");
  if (owner === "-" && group === "-") return "-";
  return `${escapeHtml(owner)} / ${escapeHtml(group)}`;
};

const renderOptionsRow = (label: string, isActive: boolean, tooltip?: string): string => {
  const cls = isActive ? "opt sel" : "opt dim";
  const title = tooltip ? ` title="${escapeHtml(tooltip)}"` : "";
  return `<span class="${cls}"${title}>${escapeHtml(label)}</span>`;
};

const renderSummary = (tar: TarParseResult, out: string[]): void => {
  const { stats, format, blockCount, blockSize, terminatorBlocks } = tar;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">TAR overview</h4>`);
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Format", escapeHtml(format?.label || "Unknown")));
  out.push(renderDefinitionRow("Header magic", escapeHtml(format?.magic || "(none)")));
  out.push(renderDefinitionRow("Version", escapeHtml(format?.version || "(n/a)")));
  out.push(
    renderDefinitionRow("Blocks (parsed)", escapeHtml(blockCount != null ? blockCount.toString() : "-"))
  );
  out.push(renderDefinitionRow("Block size", escapeHtml(`${blockSize} bytes`)));
  out.push(renderDefinitionRow("Regular files", escapeHtml(formatCount(stats.regularFiles))));
  out.push(renderDefinitionRow("Directories", escapeHtml(formatCount(stats.directories))));
  out.push(renderDefinitionRow("Symlinks", escapeHtml(formatCount(stats.symlinks))));
  out.push(renderDefinitionRow("Metadata entries", escapeHtml(formatCount(stats.metadataEntries))));
  out.push(renderDefinitionRow("Data bytes (sum)", escapeHtml(formatSize(stats.totalFileBytes))));
  out.push(renderDefinitionRow("Truncated entries", escapeHtml(formatCount(stats.truncatedEntries))));
  out.push(
    renderDefinitionRow(
      "Terminator blocks",
      escapeHtml(terminatorBlocks != null ? terminatorBlocks.toString() : "-")
    )
  );
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderFeatures = (tar: TarParseResult, out: string[]): void => {
  const features = tar.features;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Detected features</h4>`);
  const parts = [];
  const formatKind = tar.format?.kind || "unknown";
  parts.push(
    renderOptionsRow(
      formatKind === "gnu" ? "GNU" : formatKind === "posix" ? "POSIX" : "Legacy",
      true,
      "Format derived from the magic/version fields"
    )
  );
  parts.push(
    renderOptionsRow(
      "GNU long names",
      !!features.usedLongNames,
      "Uses GNU long-name (type L/N) records"
    )
  );
  parts.push(
    renderOptionsRow(
      "GNU long links",
      !!features.usedLongLinks,
      "Uses GNU long-link (type K) records"
    )
  );
  parts.push(
    renderOptionsRow(
      "PAX headers",
      !!features.usedPaxHeaders,
      "Contains POSIX.1-2001 extended attributes"
    )
  );
  parts.push(
    renderOptionsRow(
      "Global PAX",
      !!features.usedGlobalPax,
      "Contains global PAX metadata affecting subsequent entries"
    )
  );
  const checksumHealthy = (features.checksumMismatches || 0) === 0;
  parts.push(
    renderOptionsRow(
      checksumHealthy ? "Checksums ok" : "Checksum mismatches",
      checksumHealthy,
      "Whether header checksums matched the computed values"
    )
  );
  out.push(`<div class="optionsRow">${parts.join("")}</div>`);
  out.push(`</section>`);
};

const renderEntries = (tar: TarParseResult, out: string[]): void => {
  const entries = tar.entries || [];
  if (!entries.length) return;
  const limit = 200;
  const visible = entries.slice(0, limit);
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Entries</h4>`);
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>#</th><th>Name</th><th>Type</th><th>Size</th>` +
      `<th>Modified</th><th>Owner/Group</th><th>Mode</th><th>Notes</th>` +
    `</tr></thead><tbody>`
  );
  visible.forEach((entry: TarEntry) => {
    const size = escapeHtml(formatSize(entry.size));
    const modified = escapeHtml(entry.mtimeIso || "-");
    const owner = describeOwner(entry);
    const notes = describeNotes(entry);
    out.push(
      `<tr>` +
        `<td>${entry.index}</td>` +
        `<td>${escapeHtml(entry.name || "(no name)")}</td>` +
        `<td>${describeType(entry)}</td>` +
        `<td>${size}</td>` +
        `<td>${modified}</td>` +
        `<td>${owner}</td>` +
        `<td>${formatMode(entry)}</td>` +
        `<td>${notes}</td>` +
      `</tr>`
    );
  });
  out.push(`</tbody></table>`);
  if (entries.length > limit) {
    out.push(`<div class="smallNote">${entries.length - limit} more entries not shown.</div>`);
  }
  out.push(`</section>`);
};

const renderIssues = (tar: TarParseResult, out: string[]): void => {
  const issues = tar.issues || [];
  if (!issues.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>`);
  out.push(`<ul>`);
  issues.forEach(issue => out.push(`<li>${escapeHtml(issue)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

export function renderTar(tar: TarParseResult | null): string {
  if (!tar) return "";
  const out: string[] = [];
  renderSummary(tar, out);
  renderFeatures(tar, out);
  renderEntries(tar, out);
  renderIssues(tar, out);
  return out.join("");
}
