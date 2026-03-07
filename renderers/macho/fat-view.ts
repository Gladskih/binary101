"use strict";

import { dd, safe } from "../../html-utils.js";
import type { MachOFatHeader, MachOFatSlice, MachOParseResult } from "../../analyzers/macho/types.js";
import { renderImage } from "./image-view.js";
import { fatSliceCpuLabel, magicLabel } from "./header-semantics.js";
import { formatByteSize, formatHex } from "./value-format.js";

const renderFatHeader = (header: MachOFatHeader): string =>
  `<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Universal binary</h4><dl>` +
  dd("Magic", safe(`${magicLabel(header.magic)} (${formatHex(header.magic)})`)) +
  dd("Layout", safe(header.is64 ? "fat64" : "fat")) +
  dd("Endianness", safe(header.littleEndian ? "Little-endian" : "Big-endian")) +
  dd("Slices", safe(String(header.nfatArch))) +
  `</dl></section>`;

const renderSliceTable = (slices: MachOFatSlice[]): string =>
  `<div class="tableWrap"><table class="table"><thead><tr><th>#</th><th>CPU</th><th>Offset</th><th>Size</th><th>Align</th><th>Status</th></tr></thead><tbody>` +
  slices
    .map(slice => {
      const status = slice.image ? "parsed" : slice.issues[0] || "unparsed";
      return (
        `<tr><td>${slice.index}</td><td>${safe(fatSliceCpuLabel(slice))}</td>` +
        `<td><span class="mono">${safe(formatHex(slice.offset))}</span></td>` +
        `<td>${safe(formatByteSize(slice.size))}</td>` +
        `<td>2^${slice.align}</td>` +
        `<td>${safe(status)}</td></tr>`
      );
    })
    .join("") +
  `</tbody></table></div>`;

const renderSliceMeta = (slice: MachOFatSlice): string =>
  `<dl>` +
  dd("CPU", safe(fatSliceCpuLabel(slice))) +
  dd("Offset", `<span class="mono">${safe(formatHex(slice.offset))}</span>`) +
  dd("Size", safe(formatByteSize(slice.size))) +
  dd("Alignment", safe(`2^${slice.align}`)) +
  (slice.reserved == null
    ? ""
    : dd("Reserved", `<span class="mono">${safe(formatHex(slice.reserved))}</span>`)) +
  `</dl>`;

const renderSliceIssues = (slice: MachOFatSlice): string =>
  !slice.issues.length ? "" : `<ul>${slice.issues.map(issue => `<li>${safe(issue)}</li>`).join("")}</ul>`;

const renderSlice = (slice: MachOFatSlice): string =>
  `<section><details${slice.index === 0 ? " open" : ""}><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">` +
  `Slice ${slice.index}: ${safe(fatSliceCpuLabel(slice))}</summary>` +
  renderSliceMeta(slice) +
  (slice.image ? renderImage(slice.image) : "") +
  renderSliceIssues(slice) +
  `</details></section>`;

const renderFat = (result: MachOParseResult): string =>
  (result.fatHeader ? renderFatHeader(result.fatHeader) : "") +
  renderSliceTable(result.slices) +
  result.slices.map(renderSlice).join("");

export { renderFat };
