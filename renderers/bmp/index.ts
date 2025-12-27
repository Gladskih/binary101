"use strict";

import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow, renderOptionChips } from "../../html-utils.js";
import type { BmpParseResult } from "../../analyzers/bmp/types.js";
import { renderBmpColorSpace } from "./color-space.js";

const DIB_HEADER_SIZE_OPTIONS: Array<[number, string, string]> = [
  [12, "CORE", "BITMAPCOREHEADER (OS/2 1.x)"],
  [40, "INFO", "BITMAPINFOHEADER"],
  [52, "V2", "BITMAPV2INFOHEADER (masks)"],
  [56, "V3", "BITMAPV3INFOHEADER (alpha mask)"],
  [64, "OS2-2", "BITMAPINFOHEADER2 (OS/2 2.x)"],
  [108, "V4", "BITMAPV4HEADER (color space)"],
  [124, "V5", "BITMAPV5HEADER (ICC profile)"]
];

const BITS_PER_PIXEL_OPTIONS: Array<[number, string, string]> = [
  [1, "1", "Monochrome (palette index bits)"],
  [4, "4", "16-color palette"],
  [8, "8", "256-color palette"],
  [16, "16", "High color (often 5:5:5 or masks)"],
  [24, "24", "Truecolor (BGR triplets)"],
  [32, "32", "Truecolor (BGRX/BGRA or masks)"]
];

const COMPRESSION_OPTIONS: Array<[number, string, string]> = [
  [0, "BI_RGB", "Uncompressed pixels"],
  [1, "BI_RLE8", "RLE compression for 8-bit images"],
  [2, "BI_RLE4", "RLE compression for 4-bit images"],
  [3, "BI_BITFIELDS", "Uncompressed pixels with channel masks"],
  [4, "BI_JPEG", "Embedded JPEG stream"],
  [5, "BI_PNG", "Embedded PNG stream"],
  [6, "BI_ALPHABITFIELDS", "BITFIELDS with alpha mask"],
  [11, "BI_CMYK", "CMYK colorspace"],
  [12, "BI_CMYKRLE8", "CMYK RLE8"],
  [13, "BI_CMYKRLE4", "CMYK RLE4"]
];

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
      ) +
        (bmp.dibHeader.headerSize != null
          ? renderOptionChips(bmp.dibHeader.headerSize, DIB_HEADER_SIZE_OPTIONS)
          : ""),
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
      bmp.dibHeader.bitsPerPixel != null
        ? escapeHtml(String(bmp.dibHeader.bitsPerPixel)) +
            renderOptionChips(bmp.dibHeader.bitsPerPixel, BITS_PER_PIXEL_OPTIONS)
        : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Compression",
      escapeHtml(bmp.dibHeader.compressionName || "Unknown") +
        (bmp.dibHeader.compression != null
          ? renderOptionChips(bmp.dibHeader.compression, COMPRESSION_OPTIONS)
          : ""),
      "Compression codes come from the DIB header; BI_RGB indicates uncompressed pixels."
    )
  );

  if (bmp.dibHeader.planes != null) {
    out.push(
      renderDefinitionRow(
        "Planes",
        escapeHtml(String(bmp.dibHeader.planes)),
        "biPlanes / bV*Planes: must be 1 in modern BMP files."
      )
    );
  }

  if (bmp.dibHeader.imageSize != null) {
    out.push(
      renderDefinitionRow(
        "Declared image size",
        escapeHtml(formatHumanSize(bmp.dibHeader.imageSize)),
        "biSizeImage / bV*SizeImage: may be 0 for BI_RGB, otherwise stores compressed image data size."
      )
    );
  }

  if (bmp.dibHeader.xPixelsPerMeter != null || bmp.dibHeader.yPixelsPerMeter != null) {
    const ppmX = bmp.dibHeader.xPixelsPerMeter != null ? String(bmp.dibHeader.xPixelsPerMeter) : "-";
    const ppmY = bmp.dibHeader.yPixelsPerMeter != null ? String(bmp.dibHeader.yPixelsPerMeter) : "-";
    out.push(
      renderDefinitionRow(
        "Resolution",
        escapeHtml(`${ppmX} x ${ppmY} px/m`),
        "biXPelsPerMeter / biYPelsPerMeter: intended output density (often not reliable)."
      )
    );
  }

  if (bmp.dibHeader.colorsUsed != null) {
    out.push(
      renderDefinitionRow(
        "Colors used",
        escapeHtml(String(bmp.dibHeader.colorsUsed)),
        "biClrUsed: palette entries actually used; 0 means default for the bit depth."
      )
    );
  }
  if (bmp.dibHeader.importantColors != null) {
    out.push(
      renderDefinitionRow(
        "Important colors",
        escapeHtml(String(bmp.dibHeader.importantColors)),
        "biClrImportant: number of important palette colors; 0 means all are important."
      )
    );
  }

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
  out.push(renderBmpColorSpace(bmp));
  out.push(renderMasks(bmp));
  return out.join("");
};
