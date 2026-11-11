import type { ParseForUiResult } from "../analyzers/analyzer-types.js";
import { escapeHtmlText } from "../html-utils.js";
import { hex, formatHumanSize } from "../binary-utils.js";
import { isPeWindowsParseResult } from "../analyzers/pe/core/parse-result.js";
import { peSectionNameValue } from "../analyzers/pe/sections/name.js";

const table = (headers: readonly string[], rows: readonly (readonly string[])[]): string =>
  `<div class="tableWrap"><table class="table"><thead><tr>` +
  headers.map(header => `<th scope="col">${escapeHtmlText(header)}</th>`).join("") +
  `</tr></thead><tbody>` + rows.map(row => `<tr>` +
    row.map(cell => `<td>${escapeHtmlText(cell)}</td>`).join("") + `</tr>`).join("") +
  `</tbody></table></div>`;

const source = (title: string, section: string, content: string): string =>
  `<section class="nativeOverviewSection"><h4>` +
  `<button type="button" class="overviewLink" data-workspace-source="${section}">` +
  `${escapeHtmlText(title)}</button></h4>${content}</section>`;

const peOverview = (result: Extract<ParseForUiResult, { analyzer: "pe" }>): string => {
  const pe = result.parsed;
  const fields = new Set(["FileDescription", "ProductName", "ProductVersion", "FileVersion",
    "CompanyName", "OriginalFilename"]);
  const versions = isPeWindowsParseResult(pe) ? (pe.resources?.detail ?? []).flatMap(group =>
    group.entries.flatMap(entry => entry.langs.flatMap(language => {
      const values = language.versionInfo?.stringValues?.filter(value => fields.has(value.key)) ?? [];
      return values.length ? [source(`VERSION / ${entry.name ?? entry.id ?? "?"} / ` +
        `LANGID ${language.lang == null ? "?" : hex(language.lang, 4)}`, "resources",
      table(["StringFileInfo key", "Value", "String table"],
        values.map(value => [value.key, value.value, value.table])))] : [];
    }))) : [];
  if (versions.length) return versions.join("");
  return pe.sections.length ? source("Section headers", "section-headers",
    table(["Name", "PointerToRawData", "SizeOfRawData"], pe.sections.map(section =>
      [peSectionNameValue(section.name), hex(section.pointerToRawData, 8),
        formatHumanSize(section.sizeOfRawData)]))) : "";
};

const elfOverview = (result: Extract<ParseForUiResult, { analyzer: "elf" }>): string => {
  const elf = result.parsed;
  const out: string[] = [];
  if (elf.comment?.strings.length) out.push(source(".comment", "debug",
    table(["String"], elf.comment.strings.map(value => [value]))));
  const buildIds = elf.notes?.entries.filter(note => note.typeName === "NT_GNU_BUILD_ID") ?? [];
  if (buildIds.length) out.push(source("NT_GNU_BUILD_ID", "notes",
    table(["Source", "Value"], buildIds.map(note => [note.source, note.value ?? "Unavailable"]))));
  if (elf.dynamic?.needed.length) out.push(source("DT_NEEDED", "linking",
    table(["String"], elf.dynamic.needed.map(value => [value]))));
  return out.join("");
};

const mediaOverview = (result: ParseForUiResult): string => {
  if (result.analyzer !== "webm" && result.analyzer !== "mkv") return "";
  const segment = result.parsed.segment;
  if (!segment) return "";
  return (segment.info?.title ? `<h4>Info.Title</h4><p>${escapeHtmlText(segment.info.title)}</p>` : "") +
    (segment.tracks.length ? `<h4>Tracks</h4>` + table(
      ["TrackNumber", "TrackType", "CodecID", "Name", "Language"], segment.tracks.map(track =>
        [String(track.trackNumber ?? "?"), `${track.trackType ?? "?"} (${track.trackTypeLabel})`,
          track.codecId ?? "", track.name ?? "", (track.language ?? "") +
          (track.languageDefaulted ? " (default)" : "")])) : "");
};

export const renderNativeFileOverview = (result: ParseForUiResult): string => {
  if (result.analyzer === "pe") return peOverview(result);
  if (result.analyzer === "elf") return elfOverview(result);
  return mediaOverview(result);
};
