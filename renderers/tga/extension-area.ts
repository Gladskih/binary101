"use strict";

import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow, renderOptionChips } from "../../html-utils.js";
import type { TgaExtensionArea } from "../../analyzers/tga/types.js";

const ATTRIBUTES_TYPE_OPTIONS: Array<[number, string, string]> = [
  [0x00, "None", "No alpha channel data"],
  [0x01, "Alpha", "Alpha data present"],
  [0x02, "Alpha2", "Alpha data present (alternate)"],
  [0x04, "Alpha4", "Alpha data present (alternate)"],
  [0x08, "Alpha8", "Alpha data present (alternate)"]
];

export const renderTgaExtensionArea = (ext: TgaExtensionArea): string => {
  const out: string[] = [];
  out.push("<h4>Extension area</h4><dl>");
  out.push(
    renderDefinitionRow(
      "Offset",
      escapeHtml(`${ext.offset} (${toHex32(ext.offset, 8)})`),
      "Location of the v2.0 extension area."
    )
  );
  if (ext.size != null) out.push(renderDefinitionRow("Size", escapeHtml(`${ext.size} bytes`)));
  if (ext.authorName) out.push(renderDefinitionRow("Author", escapeHtml(ext.authorName)));
  if (ext.authorComment) {
    out.push(renderDefinitionRow("Author comment", `<pre class="valueHint">${escapeHtml(ext.authorComment)}</pre>`));
  }
  if (ext.timestamp) out.push(renderDefinitionRow("Timestamp", escapeHtml(ext.timestamp)));
  if (ext.jobName) out.push(renderDefinitionRow("Job name", escapeHtml(ext.jobName)));
  if (ext.jobTime) out.push(renderDefinitionRow("Job time", escapeHtml(ext.jobTime)));
  if (ext.softwareId) out.push(renderDefinitionRow("Software", escapeHtml(ext.softwareId)));
  if (ext.softwareVersion) out.push(renderDefinitionRow("Software version", escapeHtml(ext.softwareVersion)));
  if (ext.keyColor != null) out.push(renderDefinitionRow("Key color", escapeHtml(toHex32(ext.keyColor, 8))));
  if (ext.pixelAspectRatio != null) {
    out.push(renderDefinitionRow("Pixel aspect ratio", escapeHtml(ext.pixelAspectRatio.toFixed(6))));
  }
  if (ext.gamma != null) out.push(renderDefinitionRow("Gamma", escapeHtml(ext.gamma.toFixed(6))));
  if (ext.attributesType != null) {
    out.push(
      renderDefinitionRow(
        "Attributes type",
        escapeHtml(toHex32(ext.attributesType, 2)) + renderOptionChips(ext.attributesType, ATTRIBUTES_TYPE_OPTIONS),
        "AttributesType describes the alpha channel semantics for v2.0 files."
      )
    );
  }

  if (ext.colorCorrectionTable) {
    out.push(
      renderDefinitionRow(
        "Color correction table",
        escapeHtml(`${ext.colorCorrectionTable.offset} (${toHex32(ext.colorCorrectionTable.offset, 8)})`) +
          (ext.colorCorrectionTable.truncated ? '<div class="valueHint">Truncated: Yes</div>' : ""),
        "Offset to a 1000-byte color correction table (256 entries)."
      )
    );
  }
  if (ext.postageStamp) {
    const stampDims =
      ext.postageStamp.width != null && ext.postageStamp.height != null
        ? `${ext.postageStamp.width}x${ext.postageStamp.height}`
        : "Unknown";
    out.push(
      renderDefinitionRow(
        "Postage stamp",
        escapeHtml(`${stampDims} @ ${ext.postageStamp.offset} (${toHex32(ext.postageStamp.offset, 8)})`) +
          (ext.postageStamp.truncated ? '<div class="valueHint">Truncated: Yes</div>' : ""),
        "Small preview image stored inside the file (uncompressed)."
      )
    );
  }
  if (ext.scanLineTable) {
    out.push(
      renderDefinitionRow(
        "Scan-line table",
        escapeHtml(`${ext.scanLineTable.offset} (${toHex32(ext.scanLineTable.offset, 8)})`) +
          (ext.scanLineTable.truncated ? '<div class="valueHint">Truncated: Yes</div>' : ""),
        "Array of DWORD offsets, one per scanline, used for random access."
      )
    );
    if (ext.scanLineTable.expectedBytes != null) {
      out.push(renderDefinitionRow("Scan-line bytes", escapeHtml(formatHumanSize(ext.scanLineTable.expectedBytes))));
    }
  }
  out.push("</dl>");
  return out.join("");
};

