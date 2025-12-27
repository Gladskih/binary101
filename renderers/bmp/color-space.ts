"use strict";

import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow, renderOptionChips } from "../../html-utils.js";
import type { BmpParseResult } from "../../analyzers/bmp/types.js";

const COLOR_SPACE_TYPE_OPTIONS: Array<[number, string, string]> = [
  [0x00000000, "CAL_RGB", "Use endpoints + gamma (LCS_CALIBRATED_RGB)"],
  [0x73524742, "sRGB", "Standard RGB color space (LCS_sRGB)"],
  [0x57696e20, "Win", "Windows color space (LCS_WINDOWS_COLOR_SPACE)"],
  [0x4c494e4b, "LINK", "Profile linked (PROFILE_LINKED)"],
  [0x4d424544, "MBED", "Profile embedded (PROFILE_EMBEDDED)"]
];

const INTENT_OPTIONS: Array<[number, string, string]> = [
  [1, "Business", "LCS_GM_BUSINESS"],
  [2, "Graphics", "LCS_GM_GRAPHICS"],
  [4, "Images", "LCS_GM_IMAGES"],
  [8, "Abs", "LCS_GM_ABS_COLORIMETRIC"]
];

const formatFxpt2Dot30 = (value: number | null): string => {
  if (value == null) return "-";
  const numeric = value / 1073741824;
  return `${numeric.toFixed(6)} (${toHex32(value >>> 0, 8)})`;
};

const formatFxpt16Dot16 = (value: number | null): string => {
  if (value == null) return "-";
  const numeric = value / 65536;
  return `${numeric.toFixed(4)} (${toHex32(value >>> 0, 8)})`;
};

export const renderBmpColorSpace = (bmp: BmpParseResult): string => {
  const dib = bmp.dibHeader;
  if (dib.colorSpaceType == null && dib.intent == null && !dib.profile) return "";

  const out: string[] = [];
  out.push("<h4>Color space</h4>");
  out.push("<dl>");

  if (dib.colorSpaceType != null) {
    const name = dib.colorSpaceTypeName || toHex32(dib.colorSpaceType, 8);
    out.push(
      renderDefinitionRow(
        "CSType",
        escapeHtml(name) + renderOptionChips(dib.colorSpaceType, COLOR_SPACE_TYPE_OPTIONS),
        "bV4CSType / bV5CSType: defines how to interpret endpoints/gamma or profile data."
      )
    );
  }

  if (dib.endpoints) {
    out.push(
      renderDefinitionRow(
        "Endpoints",
        "<p>CIEXYZTRIPLE (fixed point 2.30). Used when CSType is LCS_CALIBRATED_RGB.</p>" +
          '<table class="byteView"><thead><tr><th>Color</th><th>X</th><th>Y</th><th>Z</th></tr></thead><tbody>' +
          "<tr>" +
            `<td>Red</td><td>${escapeHtml(formatFxpt2Dot30(dib.endpoints.red.x))}</td>` +
            `<td>${escapeHtml(formatFxpt2Dot30(dib.endpoints.red.y))}</td>` +
            `<td>${escapeHtml(formatFxpt2Dot30(dib.endpoints.red.z))}</td>` +
          "</tr>" +
          "<tr>" +
            `<td>Green</td><td>${escapeHtml(formatFxpt2Dot30(dib.endpoints.green.x))}</td>` +
            `<td>${escapeHtml(formatFxpt2Dot30(dib.endpoints.green.y))}</td>` +
            `<td>${escapeHtml(formatFxpt2Dot30(dib.endpoints.green.z))}</td>` +
          "</tr>" +
          "<tr>" +
            `<td>Blue</td><td>${escapeHtml(formatFxpt2Dot30(dib.endpoints.blue.x))}</td>` +
            `<td>${escapeHtml(formatFxpt2Dot30(dib.endpoints.blue.y))}</td>` +
            `<td>${escapeHtml(formatFxpt2Dot30(dib.endpoints.blue.z))}</td>` +
          "</tr>" +
          "</tbody></table>",
        "bV4Endpoints / bV5Endpoints: color space endpoints, stored as fixed-point values."
      )
    );
  }

  if (dib.gammaRed != null || dib.gammaGreen != null || dib.gammaBlue != null) {
    out.push(
      renderDefinitionRow(
        "Gamma",
        "<p>Fixed point 16.16. Used when CSType is LCS_CALIBRATED_RGB.</p>" +
          '<table class="byteView"><thead><tr><th>Channel</th><th>Value</th></tr></thead><tbody>' +
          `<tr><td>Red</td><td>${escapeHtml(formatFxpt16Dot16(dib.gammaRed))}</td></tr>` +
          `<tr><td>Green</td><td>${escapeHtml(formatFxpt16Dot16(dib.gammaGreen))}</td></tr>` +
          `<tr><td>Blue</td><td>${escapeHtml(formatFxpt16Dot16(dib.gammaBlue))}</td></tr>` +
          "</tbody></table>",
        "bV4Gamma* / bV5Gamma*: tone response curves per channel."
      )
    );
  }

  if (dib.intent != null) {
    out.push(
      renderDefinitionRow(
        "Intent",
        escapeHtml(dib.intentName || String(dib.intent)) + renderOptionChips(dib.intent, INTENT_OPTIONS),
        "bV5Intent: rendering intent for the embedded/linked ICC profile."
      )
    );
  }

  if (dib.profile) {
    out.push(
      renderDefinitionRow(
        "Profile",
        escapeHtml(dib.profile.kind),
        "bV5ProfileData/bV5ProfileSize are used only when CSType is PROFILE_LINKED or PROFILE_EMBEDDED."
      )
    );
    out.push(
      renderDefinitionRow(
        "Profile offset",
        escapeHtml(`${dib.profile.fileOffset} (${toHex32(dib.profile.fileOffset, 8)})`),
        "Absolute file offset computed as: fileHeaderSize(14) + bV5ProfileData."
      )
    );
    out.push(renderDefinitionRow("Profile size", escapeHtml(formatHumanSize(dib.profile.size))));
    if (dib.profile.fileName) {
      out.push(renderDefinitionRow("Profile file name", escapeHtml(dib.profile.fileName)));
    }
    if (dib.profile.embedded?.signature) {
      out.push(renderDefinitionRow("Profile signature", escapeHtml(dib.profile.embedded.signature)));
    }
    if (dib.profile.truncated) out.push(renderDefinitionRow("Profile truncated", "Yes"));
  }

  out.push("</dl>");
  return out.join("");
};

