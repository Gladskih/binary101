"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { escapeHtml, renderFlagChips } from "../../html-utils.js";
import type { PeNsisPackerFinding } from "../../analyzers/pe/packers/index.js";
import { renderOverlayDownloadButton } from "./overlay.js";

// NSIS firstheader flags come from the upstream file format definition.
// https://github.com/kichik/nsis/blob/master/Source/exehead/fileform.h
const NSIS_FLAGS: Array<[number, string, string]> = [
  [0x01, "Uninstaller", "The data belongs to an NSIS uninstaller"],
  [0x02, "Silent", "Run with silent mode enabled"],
  [0x04, "No CRC", "Do not perform the normal CRC check"],
  [0x08, "Force CRC", "Force the CRC check"]
];

const formatNsisBytes = (size: number): string =>
  size < 1024 ? `${size} bytes` : humanSize(size);

const renderNsisRow = (
  label: string,
  valueHtml: string,
  meaning: string,
  valueClass = "peNumeric"
): string =>
  `<tr><th scope="row" class="peNsisTable__field">${escapeHtml(label)}</th>` +
  `<td${valueClass ? ` class="${valueClass}"` : ""}>${valueHtml}</td>` +
  `<td class="smallNote pePackerFinding__meaning">${escapeHtml(meaning)}</td></tr>`;

export const renderNsisFindingDetails = (finding: PeNsisPackerFinding): string => {
  const dataEnd = finding.firstHeaderOffset + finding.followingDataSize;
  return `<div class="pePackerFinding__actions">` +
    `<span class="smallNote">Validated NSIS installer data</span>` +
    renderOverlayDownloadButton(
      finding.firstHeaderOffset,
      dataEnd,
      "Download NSIS installer data"
    ) +
    `</div>` +
    `<div class="tableWrap"><table class="table peNsisTable pePackerFinding__details">` +
    `<thead><tr><th>Field</th><th>Value</th><th>Meaning</th></tr></thead><tbody>` +
    renderNsisRow("Installer data start", hex(finding.firstHeaderOffset, 8),
      "File offset of the validated NSIS firstheader and installer data.") +
    renderNsisRow("Installer data end", hex(dataEnd, 8),
      "Exclusive end derived from firstheader length_of_all_following_data.") +
    renderNsisRow("Installer data size", formatNsisBytes(finding.followingDataSize),
      "Validated length_of_all_following_data value from firstheader.") +
    renderNsisRow("Compressed header size", formatNsisBytes(finding.compressedHeaderSize),
      "Declared compressed size of the NSIS header block.") +
    renderNsisRow("Flags", renderFlagChips(finding.flags, NSIS_FLAGS),
      "Validated firstheader flags; active options are highlighted.", "") +
    `</tbody></table></div>`;
};
