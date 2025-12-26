"use strict";

import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type { BmpParseResult } from "../../analyzers/bmp/types.js";

const renderWarnings = (warnings: string[] | null | undefined): string => {
  if (!warnings || warnings.length === 0) return "";
  const items = warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
};

const formatByteSize = (value: number | bigint | null | undefined): string => {
  if (value == null) return "Unknown";
  if (typeof value === "bigint") {
    if (value <= BigInt(Number.MAX_SAFE_INTEGER)) return formatHumanSize(Number(value));
    return `${value.toString()} bytes`;
  }
  return formatHumanSize(value);
};

const renderMasks = (bmp: BmpParseResult): string => {
  const masks = bmp.dibHeader.masks;
  if (!masks) return "";
  const rows: string[] = [];
  const pushRow = (label: string, value: typeof masks.red): void => {
    if (!value) return;
    const contiguous = value.contiguous ? "Yes" : "No";
    rows.push(
      "<tr>" +
        `<td>${escapeHtml(label)}</td>` +
        `<td>${escapeHtml(toHex32(value.mask, 8))}</td>` +
        `<td>${escapeHtml(String(value.shift))}</td>` +
        `<td>${escapeHtml(String(value.bits))}</td>` +
        `<td>${escapeHtml(contiguous)}</td>` +
        "</tr>"
    );
  };
  pushRow("Red", masks.red);
  pushRow("Green", masks.green);
  pushRow("Blue", masks.blue);
  pushRow("Alpha", masks.alpha);
  if (rows.length === 0) return "";
  return (
    "<h4>Masks</h4>" +
    "<p>BITFIELDS BMPs store per-channel bit masks describing how pixel bits map to RGBA.</p>" +
    '<table class="byteView"><thead><tr>' +
    "<th>Channel</th><th>Mask</th><th>Shift</th><th>Bits</th><th>Contiguous</th>" +
    `</tr></thead><tbody>${rows.join("")}</tbody></table>`
  );
};

export const renderBmp = (bmp: BmpParseResult | null): string => {
  if (!bmp) return "";

  const out: string[] = [];
  out.push("<h3>BMP structure</h3>");
  out.push("<dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(bmp.fileSize))));
  out.push(renderDefinitionRow("Signature", escapeHtml(bmp.fileHeader.signature || "Unknown")));
  out.push(
    renderDefinitionRow(
      "Declared size",
      bmp.fileHeader.declaredFileSize != null
        ? escapeHtml(formatHumanSize(bmp.fileHeader.declaredFileSize))
        : "Unknown",
      "bfSize field from the BMP file header."
    )
  );
  out.push(
    renderDefinitionRow(
      "DIB header",
      escapeHtml(
        bmp.dibHeader.headerKind
          ? `${bmp.dibHeader.headerKind} (${bmp.dibHeader.headerSize ?? "?"} bytes)`
          : "Unknown"
      ),
      "DIB (device-independent bitmap) header declares image dimensions and pixel format."
    )
  );

  const dims =
    bmp.dibHeader.width != null && bmp.dibHeader.height != null
      ? `${bmp.dibHeader.width} x ${bmp.dibHeader.height} px`
      : "Unknown";
  const orientation =
    bmp.dibHeader.topDown == null ? "" : bmp.dibHeader.topDown ? " (top-down)" : " (bottom-up)";
  out.push(renderDefinitionRow("Dimensions", escapeHtml(dims + orientation)));

  out.push(
    renderDefinitionRow(
      "Bits per pixel",
      bmp.dibHeader.bitsPerPixel != null ? escapeHtml(String(bmp.dibHeader.bitsPerPixel)) : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Compression",
      escapeHtml(bmp.dibHeader.compressionName || "Unknown"),
      "Compression codes come from the DIB header; BI_RGB indicates uncompressed pixels."
    )
  );

  if (bmp.palette) {
    out.push(
      renderDefinitionRow(
        "Palette",
        `${bmp.palette.expectedEntries ?? "?"} entries (${bmp.palette.entrySize} bytes each)`,
        "Color table entries are BGR(A) tuples stored between the DIB header and the pixel array."
      )
    );
  } else {
    out.push(
      renderDefinitionRow(
        "Palette",
        "Not present",
        "Indexed-color BMPs (<= 8 bpp) typically store a palette before the pixel array."
      )
    );
  }

  const pixelOffset =
    bmp.fileHeader.pixelArrayOffset != null ? bmp.fileHeader.pixelArrayOffset : null;
  const pixelOffsetLabel = pixelOffset != null ? `${pixelOffset} (${toHex32(pixelOffset, 8)})` : "Unknown";
  out.push(
    renderDefinitionRow(
      "Pixel array",
      escapeHtml(pixelOffsetLabel),
      "bfOffBits points to the start of pixel data."
    )
  );

  if (bmp.pixelArray) {
    out.push(
      renderDefinitionRow(
        "Row stride",
        bmp.pixelArray.rowStride != null ? escapeHtml(`${bmp.pixelArray.rowStride} bytes`) : "Unknown",
        "Each row is padded to a 4-byte boundary."
      )
    );
    out.push(
      renderDefinitionRow(
        "Pixel bytes (expected)",
        escapeHtml(formatByteSize(bmp.pixelArray.expectedBytes)),
        "Calculated for uncompressed layouts: rowStride * height."
      )
    );
    out.push(
      renderDefinitionRow(
        "Pixel bytes (available)",
        escapeHtml(formatByteSize(bmp.pixelArray.availableBytes)),
        "Bytes available in the file starting at bfOffBits."
      )
    );
  }

  out.push("</dl>");
  out.push(renderWarnings(bmp.issues));
  out.push(renderMasks(bmp));
  return out.join("");
};

