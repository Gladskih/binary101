"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import type { PngChunk, PngParseResult, PngTextChunk } from "../../analyzers/png/types.js";

function renderIssues(issues: string[] | null | undefined): string {
  if (!issues || issues.length === 0) return "";
  return `<h4>Warnings</h4><ul class="issueList">${issues
    .map(issue => `<li>${escapeHtml(issue)}</li>`)
    .join("")}</ul>`;
}

function renderTextChunks(texts: PngTextChunk[] | null | undefined): string {
  if (!texts || texts.length === 0) return "";
  const rows = texts
    .map((text, index) => {
      const keyLabel = escapeHtml(text.key || `Entry ${index + 1}`);
      const value = escapeHtml(text.value || "(empty or binary)");
      const length = text.length != null ? `${text.length} B` : "";
      return `<tr><td>${keyLabel}</td><td>${value}</td><td>${length}</td></tr>`;
    })
    .join("");
  return (
    "<h4>Text chunks</h4>" +
    '<table class="byteView">' +
    "<thead><tr>" +
    "<th>Keyword</th><th>Value</th><th>Length</th>" +
    "</tr></thead>" +
    `<tbody>${rows}</tbody></table>`
  );
}

function describeInterlace(code: number | null | undefined): string {
  if (code === 0) return "None";
  if (code === 1) return "Adam7 (7-pass interlace)";
  return code == null ? "Unknown" : `Unknown (${code})`;
}

function describeCompression(code: number | null | undefined): string {
  if (code === 0) return "Deflate/inflate (RFC 1951)";
  return code == null ? "Unknown" : `Unknown (${code})`;
}

function describeFilter(code: number | null | undefined): string {
  if (code === 0) return "Adaptive filtering (5 basic filters)";
  return code == null ? "Unknown" : `Unknown (${code})`;
}

function renderChunks(chunks: PngChunk[] | null | undefined): string {
  if (!chunks || chunks.length === 0) return "";
  const rows = chunks
    .map((chunk, index) => {
      const type = escapeHtml(chunk.type || "");
      const offset = chunk.offset != null ? chunk.offset : 0;
      const length = chunk.length != null ? chunk.length : 0;
      const trunc = chunk.truncated ? ' class="dim" title="Chunk data truncated"' : "";
      return (
        `<tr${trunc}>` +
        `<td>${index}</td>` +
        `<td>${type}</td>` +
        `<td title="${toHex32(offset, 8)}">${offset}</td>` +
        `<td title="${toHex32(length, 8)}">${length} B</td>` +
        `<td>${chunk.crc != null ? toHex32(chunk.crc, 8) : "(missing)"}</td>` +
        "</tr>"
      );
    })
    .join("");
  return (
    "<h4>Chunks</h4>" +
    "<p>PNG files are a sequence of length-prefixed chunks. " +
    "Offset shows the byte position from the start of the file. Length is the " +
    "chunk data size excluding the 4-byte length and 4-byte CRC fields.</p>" +
    '<table class="byteView"><thead><tr>' +
    "<th>#</th><th>Type</th><th>Offset</th><th>Length</th><th>CRC</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
}

function renderIhdrRows(ihdr: PngParseResult["ihdr"]): string {
  if (!ihdr) return "";
  return [
    renderDefinitionRow(
      "Channels",
      ihdr.channels != null ? String(ihdr.channels) : "?",
      "Number of color channels used per pixel (including alpha when present)."
    ),
    renderDefinitionRow(
      "Bytes per pixel",
      ihdr.bytesPerPixel != null ? String(ihdr.bytesPerPixel) : "Unknown",
      "Calculated from bit depth and channels; drives expected row sizes."
    ),
    renderDefinitionRow(
      "Compression",
      escapeHtml(describeCompression(ihdr.compression)),
      "PNG always uses zlib/deflate (method 0). Other values are invalid."
    ),
    renderDefinitionRow(
      "Filter method",
      escapeHtml(describeFilter(ihdr.filter)),
      "Filter method 0 enables per-row adaptive filters before compression."
    ),
    renderDefinitionRow(
      "Interlace",
      escapeHtml(describeInterlace(ihdr.interlace)),
      "Adam7 interlace allows progressive display; non-interlaced images read top to bottom."
    )
  ].join("");
}

function renderMetadataRows(png: PngParseResult): string {
  const { paletteEntries, hasTransparency, gamma, iccProfile, physical } = png;
  const densityValue = physical
    ? `${physical.pixelsPerUnitX} x ${physical.pixelsPerUnitY} ${
        physical.unitSpecifier === 1 ? "per meter" : "(unit unknown)"
      }`
    : "Not provided";
  return [
    renderDefinitionRow(
      "Palette",
      paletteEntries > 0 ? `${paletteEntries} entries` : "Not present",
      "Indexed-color PNGs expect a PLTE chunk with RGB palette entries."
    ),
    renderDefinitionRow(
      "Transparency",
      hasTransparency ? "Alpha or tRNS present" : "No alpha markers found",
      "Alpha can come from RGBA color types or a tRNS transparency chunk."
    ),
    renderDefinitionRow(
      "Gamma",
      gamma != null ? gamma.toString() : "Not specified",
      "gAMA stores the file gamma (value = actual gamma Ã— 100000)."
    ),
    renderDefinitionRow(
      "ICC profile",
      iccProfile ? escapeHtml(iccProfile.name) : "Not embedded",
      "iCCP can embed a compressed ICC color profile for accurate color management."
    ),
    renderDefinitionRow(
      "Pixel density",
      densityValue,
      physical
        ? "pHYs defines intended pixel density for display or printing."
        : "pHYs chunk is optional; many PNGs omit pixel density."
    )
  ].join("");
}

function renderStructureRows(png: PngParseResult): string {
  return [
    renderDefinitionRow(
      "Image data",
      `${png.idatChunks} IDAT chunk(s), ${formatHumanSize(png.idatSize)}`,
      "Image data is stored in one or more IDAT chunks that form a single zlib stream."
    ),
    renderDefinitionRow(
      "Chunk count",
      String(png.chunkCount),
      "Total chunk headers parsed from the file."
    ),
    renderDefinitionRow(
      "First chunk",
      escapeHtml(png.firstChunkType || "Unknown"),
      "PNG files must start with IHDR immediately after the signature."
    ),
    renderDefinitionRow(
      "IEND",
      png.sawIend ? "Present" : "Missing",
      "IEND should be the final chunk; missing IEND often means truncation or appended data."
    )
  ].join("");
}

export function renderPng(png: PngParseResult | null): string {
  if (!png) return "";
  const out: string[] = [];
  const colorSummary = png.ihdr ? `${png.ihdr.colorName} (${png.ihdr.bitDepth}-bit)` : "Unknown";
  out.push("<h3>PNG structure</h3>");
  out.push("<dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(png.size))));
  out.push(
    png.ihdr && png.ihdr.width && png.ihdr.height
      ? renderDefinitionRow("Dimensions", `${png.ihdr.width} x ${png.ihdr.height} px`)
      : renderDefinitionRow("Dimensions", "Unknown")
  );
  out.push(
    renderDefinitionRow(
      "Color type",
      escapeHtml(colorSummary),
      "Color model and bit depth declared in the IHDR chunk."
    )
  );
  out.push(renderIhdrRows(png.ihdr));
  out.push(renderMetadataRows(png));
  out.push(renderStructureRows(png));
  out.push("</dl>");
  out.push(renderIssues(png.issues));
  out.push(renderTextChunks(png.texts));
  out.push(renderChunks(png.chunks));
  return out.join("");
}
