// @ts-nocheck
"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";

function renderIssues(issues) {
  if (!issues || issues.length === 0) return "";
  const bulletItems = issues
    .map(issue => `<li>${escapeHtml(issue)}</li>`)
    .join("");
  return `<h4>Warnings</h4><ul class="issueList">${bulletItems}</ul>`;
}

function renderTextChunks(texts) {
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

function describeInterlace(code) {
  if (code === 0) return "None";
  if (code === 1) return "Adam7 (7-pass interlace)";
  return code == null ? "Unknown" : `Unknown (${code})`;
}

function describeCompression(code) {
  if (code === 0) return "Deflate/inflate (RFC 1951)";
  return code == null ? "Unknown" : `Unknown (${code})`;
}

function describeFilter(code) {
  if (code === 0) return "Adaptive filtering (5 basic filters)";
  return code == null ? "Unknown" : `Unknown (${code})`;
}

function renderChunks(chunks) {
  if (!chunks || chunks.length === 0) return "";
  const header =
    "<h4>Chunks</h4>" +
    "<p>PNG files are a sequence of length-prefixed chunks. " +
    "Offset shows the byte position from the start of the file. Length is the " +
    "chunk data size excluding the 4-byte length and 4-byte CRC fields.</p>";
  const rows = chunks
    .map((chunk, index) => {
      const type = escapeHtml(chunk.type || "");
      const offset = chunk.offset != null ? chunk.offset : 0;
      const length = chunk.length != null ? chunk.length : 0;
      const crc = chunk.crc != null ? toHex32(chunk.crc, 8) : "(missing)";
      const offsetHex = toHex32(offset, 8);
      const lengthHex = toHex32(length, 8);
      const trunc = chunk.truncated
        ? " class=\"dim\" title=\"Chunk data truncated\""
        : "";
      return (
        `<tr${trunc}>` +
        `<td>${index}</td>` +
        `<td>${type}</td>` +
        `<td title="${offsetHex}">${offset}</td>` +
        `<td title="${lengthHex}">${length} B</td>` +
        `<td>${crc}</td>` +
        "</tr>"
      );
    })
    .join("");
  return (
    header +
    '<table class="byteView"><thead><tr>' +
    "<th>#</th><th>Type</th><th>Offset</th><th>Length</th><th>CRC</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
}

export function renderPng(png) {
  if (!png) return "";
  const {
    size,
    ihdr,
    chunkCount,
    firstChunkType,
    paletteEntries,
    hasTransparency,
    gamma,
    iccProfile,
    physical,
    idatChunks,
    idatSize,
    sawIend,
    texts,
    chunks,
    issues
  } = png;

  const out = [];
  out.push("<h3>PNG structure</h3>");
  out.push("<dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(size))));
  if (ihdr && ihdr.width && ihdr.height) {
    out.push(
      renderDefinitionRow("Dimensions", `${ihdr.width} x ${ihdr.height} px`)
    );
  } else {
    out.push(renderDefinitionRow("Dimensions", "Unknown"));
  }
  const colorSummary = ihdr
    ? `${ihdr.colorName} (${ihdr.bitDepth}-bit)`
    : "Unknown";
  out.push(
    renderDefinitionRow(
      "Color type",
      escapeHtml(colorSummary),
      "Color model and bit depth declared in the IHDR chunk."
    )
  );
  if (ihdr) {
    out.push(
      renderDefinitionRow(
        "Channels",
        ihdr.channels != null ? String(ihdr.channels) : "?",
        "Number of color channels used per pixel (including alpha when present)."
      )
    );
    out.push(
      renderDefinitionRow(
        "Bytes per pixel",
        ihdr.bytesPerPixel != null ? String(ihdr.bytesPerPixel) : "Unknown",
        "Calculated from bit depth and channels; drives expected row sizes."
      )
    );
    out.push(
      renderDefinitionRow(
        "Compression",
        escapeHtml(describeCompression(ihdr.compression)),
        "PNG always uses zlib/deflate (method 0). Other values are invalid."
      )
    );
    out.push(
      renderDefinitionRow(
        "Filter method",
        escapeHtml(describeFilter(ihdr.filter)),
        "Filter method 0 enables per-row adaptive filters before compression."
      )
    );
    out.push(
      renderDefinitionRow(
        "Interlace",
        escapeHtml(describeInterlace(ihdr.interlace)),
        "Adam7 interlace allows progressive display; non-interlaced images read top to bottom."
      )
    );
  }
  out.push(
    renderDefinitionRow(
      "Palette",
      paletteEntries > 0 ? `${paletteEntries} entries` : "Not present",
      "Indexed-color PNGs expect a PLTE chunk with RGB palette entries."
    )
  );
  out.push(
    renderDefinitionRow(
      "Transparency",
      hasTransparency ? "Alpha or tRNS present" : "No alpha markers found",
      "Alpha can come from RGBA color types or a tRNS transparency chunk."
    )
  );
  out.push(
    renderDefinitionRow(
      "Gamma",
      gamma != null ? gamma.toString() : "Not specified",
      "gAMA stores the file gamma (value = actual gamma × 100000)."
    )
  );
  out.push(
    renderDefinitionRow(
      "ICC profile",
      iccProfile ? escapeHtml(iccProfile.name) : "Not embedded",
      "iCCP can embed a compressed ICC color profile for accurate color management."
    )
  );
  if (physical) {
    const unit = physical.unitSpecifier === 1 ? "per meter" : "(unit unknown)";
    out.push(
      renderDefinitionRow(
        "Pixel density",
        `${physical.pixelsPerUnitX} x ${physical.pixelsPerUnitY} ${unit}`,
        "pHYs defines intended pixel density for display or printing."
      )
    );
  } else {
    out.push(
      renderDefinitionRow(
        "Pixel density",
        "Not provided",
        "pHYs chunk is optional; many PNGs omit pixel density."
      )
    );
  }
  out.push(
    renderDefinitionRow(
      "Image data",
      `${idatChunks} IDAT chunk(s), ${formatHumanSize(idatSize)}`,
      "Image data is stored in one or more IDAT chunks that form a single zlib stream."
    )
  );
  out.push(
    renderDefinitionRow(
      "Chunk count",
      String(chunkCount),
      "Total chunk headers parsed from the file."
    )
  );
  out.push(
    renderDefinitionRow(
      "First chunk",
      escapeHtml(firstChunkType || "Unknown"),
      "PNG files must start with IHDR immediately after the signature."
    )
  );
  out.push(
    renderDefinitionRow(
      "IEND",
      sawIend ? "Present" : "Missing",
      "IEND should be the final chunk; missing IEND often means truncation or appended data."
    )
  );
  out.push("</dl>");

  out.push(renderIssues(issues));
  out.push(renderTextChunks(texts));
  out.push(renderChunks(chunks));

  return out.join("");
}
