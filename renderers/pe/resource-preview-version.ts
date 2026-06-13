"use strict";
import { escapeHtml } from "../../html-utils.js";
import type { ResourceVersionPreview } from "../../analyzers/pe/resources/preview/types.js";
import { formatWindowsLanguageName } from "./windows-language-names.js";

// Number.prototype.toString uses radix 16 for hexadecimal output; each byte is
// represented by two hex digits when formatting fixed-width DWORD values.
const HEX_RADIX = 16;
const HEX_DIGITS_PER_BYTE = 2;
const DWORD_HEX_DIGITS = Uint32Array.BYTES_PER_ELEMENT * HEX_DIGITS_PER_BYTE;

const renderDefinitionRows = (rows: Array<{ label: string; value: string }>): string => {
  if (!rows.length) return "";
  const cells = rows
    .map(row =>
      `<div><span class="mono">${escapeHtml(row.label)}</span></div>` +
      `<div style="min-width:0;overflow-wrap:anywhere">${escapeHtml(row.value)}</div>`
    )
    .join("");
  return `<div class="smallNote" style="display:grid;grid-template-columns:max-content 1fr;gap:.15rem .55rem;margin-top:.2rem">${cells}</div>`;
};

const parseVersionTableTranslation = (
  table: string
): { languageId: number; codePage: number } | null => {
  // StringFileInfo table names encode LANGID and code page as 8 hex digits, e.g. 040904E4.
  // Source: https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource
  if (!/^[0-9a-fA-F]{8}$/.test(table)) return null;
  return {
    languageId: Number.parseInt(table.slice(0, 4), HEX_RADIX),
    codePage: Number.parseInt(table.slice(4), HEX_RADIX)
  };
};

const formatVersionTranslation = (languageId: number, codePage: number): string =>
  `${formatWindowsLanguageName(languageId)} / CP${codePage}`;

const formatVersionTableName = (table: string): string => {
  const translation = parseVersionTableTranslation(table);
  return translation
    ? formatVersionTranslation(translation.languageId, translation.codePage)
    : table;
};

const createTranslationKey = (languageId: number, codePage: number): string =>
  `${languageId}:${codePage}`;

const formatDwordHex = (value: number): string =>
  `0x${(value >>> 0).toString(HEX_RADIX).padStart(DWORD_HEX_DIGITS, "0")}`;

const collectVersionTableTranslations = (info: ResourceVersionPreview): Set<string> => {
  const translations = new Set<string>();
  for (const entry of info.stringValues || []) {
    const translation = parseVersionTableTranslation(entry.table);
    if (!translation) continue;
    translations.add(createTranslationKey(translation.languageId, translation.codePage));
  }
  return translations;
};

const renderVersionTranslations = (
  info: ResourceVersionPreview,
  tableTranslations: Set<string>
): string => {
  const translations = (info.translations || []).filter(entry =>
    !tableTranslations.has(createTranslationKey(entry.languageId, entry.codePage))
  );
  if (!translations.length) return "";
  const rows = translations
    .map(entry => `<li>${escapeHtml(formatVersionTranslation(entry.languageId, entry.codePage))}</li>`)
    .join("");
  return `<div class="smallNote" style="margin-top:.35rem"><b>Declared translations</b><ul style="padding-left:1.1rem;margin:.2rem 0 0 0">${rows}</ul></div>`;
};

const renderVersionFixedInfo = (info: ResourceVersionPreview): string => {
  const rows = [
    info.fixedFileInfo
      ? {
          label: "StructVersion",
          value: `${info.fixedFileInfo.structVersionMajor}.${info.fixedFileInfo.structVersionMinor} `
            + `(${formatDwordHex(info.fixedFileInfo.structVersionRaw)})`
        }
      : null,
    info.fileVersionString
      ? { label: "FileVersion", value: info.fileVersionString }
      : null,
    info.productVersionString
      ? { label: "ProductVersion", value: info.productVersionString }
      : null
  ].filter((row): row is { label: string; value: string } => Boolean(row));
  return rows.length
    ? `<div class="smallNote"><b>Fixed version info</b>${renderDefinitionRows(rows)}</div>`
    : "";
};

const renderVersionStringTables = (info: ResourceVersionPreview): string => {
  if (!info.stringValues?.length) return "";
  const stringsByTable = new Map<string, Array<{ key: string; value: string }>>();
  for (const entry of info.stringValues) {
    if (entry.key === "FileVersion" && entry.value === info.fileVersionString) continue;
    if (entry.key === "ProductVersion" && entry.value === info.productVersionString) continue;
    const tableEntries = stringsByTable.get(entry.table) || [];
    tableEntries.push({ key: entry.key, value: entry.value });
    stringsByTable.set(entry.table, tableEntries);
  }
  return [...stringsByTable.entries()].map(([table, values]) =>
    values.length
      ? `<div class="smallNote" style="margin-top:.35rem"><b>${escapeHtml(formatVersionTableName(table))}</b>${renderDefinitionRows(values.map(value => ({ label: value.key, value: value.value })))}</div>`
      : ""
  ).join("");
};

export const renderVersionPreview = (info: ResourceVersionPreview): string => {
  const tableTranslations = collectVersionTableTranslations(info);
  return [
    renderVersionFixedInfo(info),
    renderVersionTranslations(info, tableTranslations),
    renderVersionStringTables(info)
  ].join("");
};
