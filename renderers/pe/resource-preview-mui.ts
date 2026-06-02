"use strict";

import { escapeHtml } from "../../html-utils.js";
import {
  getMuiResourceFileTypeLabel,
  type MuiResourceConfiguration
} from "../../analyzers/pe/resources/mui-config.js";
import { knownResourceType } from "../../analyzers/pe/resources/type-names.js";

const formatHex = (value: number, width = 8): string =>
  `0x${value.toString(16).padStart(width, "0")}`;

const formatChecksum = (value: string): string =>
  value.replace(/(.{8})/gu, "$1 ").trim();

const renderFieldRows = (rows: Array<{ label: string; value: string }>): string =>
  `<table class="table peResourceFieldTable"><tbody>${rows
    .map(row => `<tr><th scope="row">${escapeHtml(row.label)}</th><td>${row.value}</td></tr>`)
    .join("")}</tbody></table>`;

const renderStringList = (values: string[]): string =>
  values.length
    ? values.map(value => `<span class="mono">${escapeHtml(value)}</span>`).join(", ")
    : '<span class="smallNote">(none)</span>';

const formatResourceTypeId = (id: number): string => {
  const label = knownResourceType(id);
  return label ? `#${id} (${label})` : `#${id}`;
};

const renderResourceTypeList = (
  title: string,
  names: string[],
  ids: number[]
): string => {
  const rows = [
    ...names.map(name => ({ kind: "Name", value: name })),
    ...ids.map(id => ({ kind: "ID", value: formatResourceTypeId(id) }))
  ];
  if (!rows.length) {
    return `<div class="smallNote" style="margin-top:.35rem"><b>${escapeHtml(title)}</b>: (none)</div>`;
  }
  return (
    `<div style="margin-top:.45rem"><b>${escapeHtml(title)}</b>` +
    `<table class="table peResourceNestedTable"><thead><tr><th>Kind</th><th>Resource type</th></tr></thead>` +
    `<tbody>${rows
      .map(row => `<tr><td>${escapeHtml(row.kind)}</td><td class="mono">${escapeHtml(row.value)}</td></tr>`)
      .join("")}</tbody></table></div>`
  );
};

const renderUnknownPairs = (config: MuiResourceConfiguration): string => {
  const rows = [
    { label: "Reserved/unknown #1", values: config.unknown1 },
    { label: "Reserved/unknown #2", values: config.unknown2 }
  ].filter(row => row.values.some(value => value !== 0));
  if (!rows.length) return "";
  return renderFieldRows(rows.map(row => ({
    label: row.label,
    value: `<span class="mono">${escapeHtml(row.values.map(value => formatHex(value)).join(", "))}</span>`
  })));
};

export const renderMuiConfigPreview = (config: MuiResourceConfiguration): string => {
  const fields = renderFieldRows([
    { label: "Declared size", value: `${config.declaredSize} bytes` },
    { label: "Version", value: `<span class="mono">${escapeHtml(formatHex(config.version))}</span>` },
    {
      label: "File type",
      value:
        `${escapeHtml(getMuiResourceFileTypeLabel(config.fileType))} ` +
        `<span class="mono">(${escapeHtml(formatHex(config.fileType))})</span>`
    },
    { label: "Path type", value: `<span class="mono">${escapeHtml(formatHex(config.pathType))}</span>` },
    {
      label: "System attributes",
      value: `<span class="mono">${escapeHtml(formatHex(config.systemAttributes))}</span>`
    },
    {
      label: "Fallback location",
      value: `<span class="mono">${escapeHtml(formatHex(config.fallbackLocation))}</span>`
    },
    { label: "Language", value: escapeHtml(config.languageName || "(none)") },
    { label: "Ultimate fallback", value: escapeHtml(config.fallbackLanguageName || "(none)") },
    { label: "MUI path", value: renderStringList(config.muiPaths) },
    { label: "Checksum", value: `<span class="mono">${escapeHtml(formatChecksum(config.checksum))}</span>` },
    {
      label: "Service checksum",
      value: `<span class="mono">${escapeHtml(formatChecksum(config.serviceChecksum))}</span>`
    },
    { label: "Trailing bytes", value: `${config.trailingByteCount}` }
  ]);
  return [
    `<div class="smallNote"><b>MUI resource configuration</b></div>`,
    fields,
    renderUnknownPairs(config),
    renderResourceTypeList("Language-neutral / main resource types", config.mainTypeNames, config.mainTypeIds),
    renderResourceTypeList("Language-specific MUI resource types", config.muiTypeNames, config.muiTypeIds)
  ].join("");
};
