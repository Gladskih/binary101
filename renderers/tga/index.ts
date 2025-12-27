"use strict";

import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow, renderOptionChips } from "../../html-utils.js";
import type { TgaParseResult } from "../../analyzers/tga/types.js";
import { renderTgaDeveloperDirectory } from "./developer-directory.js";
import { renderTgaExtensionArea } from "./extension-area.js";

const COLOR_MAP_TYPE_OPTIONS: Array<[number, string, string]> = [
  [0, "None", "No color map"],
  [1, "Present", "Color map included in file"]
];

const IMAGE_TYPE_OPTIONS: Array<[number, string, string]> = [
  [0, "None", "No image data"],
  [1, "CMAP", "Color-mapped, uncompressed"],
  [2, "RGB", "Truecolor, uncompressed"],
  [3, "Gray", "Monochrome, uncompressed"],
  [9, "CMAP-RLE", "Color-mapped, RLE compressed"],
  [10, "RGB-RLE", "Truecolor, RLE compressed"],
  [11, "Gray-RLE", "Monochrome, RLE compressed"]
];

const PIXEL_DEPTH_OPTIONS: Array<[number, string, string]> = [
  [8, "8", "Common for grayscale or palette indices"],
  [15, "15", "Common for 5:5:5 + 1 attribute bit"],
  [16, "16", "Common for 5:5:5/5:6:5 + attribute bits"],
  [24, "24", "Truecolor BGR"],
  [32, "32", "Truecolor BGRA (with attribute bits)"]
];

const ORIGIN_OPTIONS: Array<[number, string, string]> = [
  [0x00, "BL", "Origin at bottom-left (bits 4-5 = 00)"],
  [0x10, "BR", "Origin at bottom-right (bits 4-5 = 01)"],
  [0x20, "TL", "Origin at top-left (bits 4-5 = 10)"],
  [0x30, "TR", "Origin at top-right (bits 4-5 = 11)"]
];

const renderWarnings = (warnings: string[] | null | undefined): string => {
  if (!warnings || warnings.length === 0) return "";
  const items = warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
};

const formatBigIntBytes = (value: bigint): string => {
  if (value <= BigInt(Number.MAX_SAFE_INTEGER)) return formatHumanSize(Number(value));
  return `${value.toString()} bytes`;
};

export const renderTga = (tga: TgaParseResult | null): string => {
  if (!tga) return "";
  const header = tga.header;

  const out: string[] = [];
  out.push("<h3>TGA structure</h3>");
  out.push("<dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(tga.fileSize))));
  out.push(
    renderDefinitionRow(
      "Version",
      escapeHtml(tga.version),
      "TGA v2.0 is detected via the TRUEVISION-XFILE footer signature."
    )
  );

  if (header.imageType != null) {
    out.push(
      renderDefinitionRow(
        "Image type",
        escapeHtml(header.imageTypeName || String(header.imageType)) +
          renderOptionChips(header.imageType, IMAGE_TYPE_OPTIONS),
        "Header ImageType field describes the pixel encoding and whether RLE is used."
      )
    );
  } else {
    out.push(renderDefinitionRow("Image type", "Unknown"));
  }

  if (header.colorMapType != null) {
    out.push(
      renderDefinitionRow(
        "Color map",
        escapeHtml(header.colorMapTypeName || String(header.colorMapType)) +
          renderOptionChips(header.colorMapType, COLOR_MAP_TYPE_OPTIONS),
        "ColorMapType indicates whether a palette is included."
      )
    );
  }

  const dimensions =
    header.width != null && header.height != null ? `${header.width} x ${header.height} px` : "Unknown";
  out.push(renderDefinitionRow("Dimensions", escapeHtml(dimensions)));

  if (header.pixelDepth != null) {
    out.push(
      renderDefinitionRow(
        "Pixel depth",
        escapeHtml(`${header.pixelDepth} bits`) + renderOptionChips(header.pixelDepth, PIXEL_DEPTH_OPTIONS),
        "PixelDepth includes any attribute/alpha bits."
      )
    );
  }

  if (header.imageDescriptor != null) {
    const originCode = header.imageDescriptor & 0x30;
    out.push(
      renderDefinitionRow(
        "Origin",
        escapeHtml(header.origin || "Unknown") + renderOptionChips(originCode, ORIGIN_OPTIONS),
        "ImageDescriptor bits 4-5 define the origin corner (coordinate 0,0)."
      )
    );
    if (header.attributeBitsPerPixel != null) {
      out.push(
        renderDefinitionRow(
          "Attribute bits",
          escapeHtml(String(header.attributeBitsPerPixel)),
          "ImageDescriptor bits 0-3: number of attribute bits per pixel."
        )
      );
    }
    if (header.reservedDescriptorBits) {
      out.push(
        renderDefinitionRow(
          "Descriptor reserved bits",
          escapeHtml(toHex32(header.reservedDescriptorBits, 2)),
          "Bits 6-7 are expected to be 0 in the TGA header."
        )
      );
    }
  }

  if (tga.imageId) {
    const idValue = tga.imageId.text
      ? escapeHtml(tga.imageId.text)
      : escapeHtml(tga.imageId.previewHex || "Binary");
    out.push(
      renderDefinitionRow(
        "Image ID",
        `${escapeHtml(formatHumanSize(tga.imageId.length))} @ ${escapeHtml(
          `${tga.imageId.offset} (${toHex32(tga.imageId.offset, 8)})`
        )}<div class="valueHint">${idValue}</div>`,
        "Optional image identification field right after the 18-byte header."
      )
    );
  } else {
    out.push(
      renderDefinitionRow(
        "Image ID",
        "Not present",
        "IDLength is 0 when there is no image identification field."
      )
    );
  }

  if (tga.colorMap) {
    const cmap = tga.colorMap;
    out.push(
      renderDefinitionRow(
        "Color map data",
        escapeHtml(
          `${cmap.lengthEntries ?? "?"} entries, ${cmap.entryBits ?? "?"} bits each (${cmap.expectedBytes ?? "?"} bytes)`
        ) +
          `<div class="valueHint">Offset: ${escapeHtml(`${cmap.offset} (${toHex32(cmap.offset, 8)})`)}</div>` +
          (cmap.truncated ? '<div class="valueHint">Truncated: Yes</div>' : ""),
        "Palette data stored between the Image ID field and image data."
      )
    );
  }

  if (tga.imageData.offset != null) {
    out.push(
      renderDefinitionRow(
        "Image data offset",
        escapeHtml(`${tga.imageData.offset} (${toHex32(tga.imageData.offset, 8)})`),
        "Start of pixel data after header, optional ID, and optional color map."
      )
    );
  }
  if (tga.imageData.availableBytes != null) {
    out.push(
      renderDefinitionRow(
        "Image data bytes (available)",
        escapeHtml(formatHumanSize(tga.imageData.availableBytes)),
        "Bytes until the footer/metadata region (when present) or until EOF."
      )
    );
  }
  if (tga.imageData.expectedDecodedBytes != null) {
    const decodedText = formatBigIntBytes(tga.imageData.expectedDecodedBytes);
    const hint = tga.imageData.decodedBytesHint
      ? `<div class="valueHint">${escapeHtml(tga.imageData.decodedBytesHint)}</div>`
      : "";
    out.push(
      renderDefinitionRow(
        "Decoded pixel bytes",
        escapeHtml(decodedText) + hint,
        "Uncompressed pixel buffer size: width * height * bytesPerPixel."
      )
    );
  }

  if (tga.footer?.present) {
    out.push(renderDefinitionRow("Footer signature", escapeHtml(tga.footer.signature || "Unknown")));
    if (tga.footer.extensionOffset != null) {
      out.push(
        renderDefinitionRow(
          "Extension area offset",
          escapeHtml(`${tga.footer.extensionOffset} (${toHex32(tga.footer.extensionOffset, 8)})`),
          "ExtensionOffset points to the 495-byte v2.0 extension area (0 means none)."
        )
      );
    }
    if (tga.footer.developerDirectoryOffset != null) {
      out.push(
        renderDefinitionRow(
          "Developer directory offset",
          escapeHtml(`${tga.footer.developerDirectoryOffset} (${toHex32(tga.footer.developerDirectoryOffset, 8)})`),
          "DeveloperOffset points to the developer directory table (0 means none)."
        )
      );
    }
  }

  out.push("</dl>");
  out.push(renderWarnings(tga.issues));
  if (tga.extensionArea) out.push(renderTgaExtensionArea(tga.extensionArea));
  if (tga.developerDirectory) out.push(renderTgaDeveloperDirectory(tga.developerDirectory));
  return out.join("");
};

