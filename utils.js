"use strict";

export const nowIsoString = () => new Date().toISOString();

export const formatHumanSize = byteCount => {
  const base = 1024;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let unitIndex = 0;
  let value = byteCount;
  while (value >= base && unitIndex < units.length - 1) {
    value /= base;
    unitIndex++;
  }
  const roundedValue = value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
  return `${roundedValue} ${units[unitIndex]} (${byteCount} bytes)`;
};

export const toHex32 = (value, width = 0) => {
  const masked = Number(value >>> 0);
  return "0x" + masked.toString(16).padStart(width, "0");
};

export const toHex64 = value => "0x" + value.toString(16);

export const escapeHtml = input =>
  String(input)
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;");

export const renderDefinitionRow = (label, valueHtml, tooltip) =>
  `<dt${tooltip ? ` title="${escapeHtml(tooltip)}"` : ""}>${label}</dt><dd>${valueHtml}</dd>`;

export const renderOptionChips = (selectedCode, options) =>
  `<div class="optionsRow">${options
    .map(([code, label]) =>
      `<span class="opt ${code === selectedCode ? "sel" : "dim"}" title="${escapeHtml(
        `${label} (${toHex32(code, 4)})`
      )}">${label}</span>`
    )
    .join("")}
  </div>`;

export const renderFlagChips = (mask, flags) =>
  `<div class="optionsRow">${flags
    .map(([bit, name, explanation]) => {
      const isSet = (mask & bit) !== 0;
      const label = explanation ? `${name} - ${explanation}` : name;
      const tooltip = `${label} (${toHex32(bit, 4)})`;
      return `<span class="opt ${isSet ? "sel" : "dim"}" title="${escapeHtml(tooltip)}">${name}</span>`;
    })
    .join("")}
  </div>`;

export const formatUnixSecondsOrDash = unixSeconds => {
  if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return "-";
  const date = new Date(unixSeconds * 1000);
  const year = date.getUTCFullYear();
  const iso = date.toISOString();
  return year < 1990 || year > 2100 ? `${iso} (unusual)` : iso;
};

export const readAsciiString = (dataView, offset, maxLength) => {
  let result = "";
  for (let index = 0; index < maxLength && offset + index < dataView.byteLength; index++) {
    const codePoint = dataView.getUint8(offset + index);
    if (codePoint === 0) break;
    result += String.fromCharCode(codePoint);
  }
  return result;
};

export const isPrintableByte = byteValue => byteValue >= 0x20 && byteValue <= 0x7e;

export const collectPrintableRuns = (bytes, minimumLength) => {
  const runs = [];
  let current = "";
  for (const byteValue of bytes) {
    if (isPrintableByte(byteValue)) {
      current += String.fromCharCode(byteValue);
      if (current.length > 4096) {
        runs.push(current);
        current = "";
      }
    } else if (current.length >= minimumLength) {
      runs.push(current);
      current = "";
    } else {
      current = "";
    }
  }
  if (current.length >= minimumLength) runs.push(current);
  return runs;
};

export const bufferToHex = arrayBuffer =>
  [...new Uint8Array(arrayBuffer)]
    .map(byteValue => byteValue.toString(16).padStart(2, "0"))
    .join("");

export const alignUpTo = (value, alignment) => {
  if (!alignment) return value >>> 0;
  const mask = (alignment - 1) >>> 0;
  return ((value + mask) & ~mask) >>> 0;
};

// Backwards-compatible aliases kept while refactoring callers.
export const nowIso = nowIsoString;
export const humanSize = formatHumanSize;
export const hex = toHex32;
export const hex64 = toHex64;
export const safe = escapeHtml;
export const dd = renderDefinitionRow;
export const rowOpts = renderOptionChips;
export const rowFlags = renderFlagChips;
export const isoOrDash = formatUnixSecondsOrDash;
export const ascii = readAsciiString;
export const printable = isPrintableByte;
export const runStrings = collectPrintableRuns;
export const bufToHex = bufferToHex;
export const alignUp = alignUpTo;
