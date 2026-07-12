"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type { PeInnoSetupFinding } from "../../analyzers/pe/packers/index.js";
import { renderDownloadButton } from "../download-button.js";

const renderRow = (label: string, value: string, meaning: string): string =>
  `<tr><th scope="row" class="peInnoTable__field">${escapeHtml(label)}</th>` +
  `<td class="peNumeric">${escapeHtml(value)}</td>` +
  `<td class="smallNote pePackerFinding__meaning">${escapeHtml(meaning)}</td></tr>`;

const renderEngineDownload = (finding: PeInnoSetupFinding): string =>
  renderDownloadButton("Download embedded setup engine", [
    ["data-pe-inno-engine-download"],
    ["data-inno-table-offset", finding.offsetTableOffset]
  ]);

export const renderInnoSetupFindingDetails = (finding: PeInnoSetupFinding): string =>
  `<div class="tableWrap"><table class="table peInnoTable pePackerFinding__details">` +
  `<thead><tr><th>Field</th><th>Value</th><th>Meaning</th></tr></thead><tbody>` +
  renderRow("Loader table", hex(finding.offsetTableOffset, 8),
    "File offset of the CRC-validated RCDATA 11111 loader table.") +
  renderRow("Embedded data start", hex(finding.dataOffset, 8),
    "Start of the embedded Inno Setup data slices.") +
  renderRow("Setup headers start", hex(finding.headerOffset, 8),
    "Start of the compressed installer metadata headers.") +
  renderRow("Setup engine block", hex(finding.setupExeOffset, 8),
    "Start of the validated compressed setup-engine block.") +
  renderRow("Packed engine size", humanSize(finding.setupExeStoredSize),
    "Stored block bytes, including per-chunk CRC-32 fields.") +
  renderRow("Unpacked engine size", humanSize(finding.setupExeUnpackedSize),
    "Decoded PE size declared by the loader offset table.") +
  renderRow("Installer data end", hex(finding.totalSize, 8),
    "Exclusive total-size boundary from the loader offset table.") +
  `</tbody></table></div><div class="pePackerFinding__actions">` +
  `<span class="smallNote">Decoded LZMA and reversed Inno x86 call filter</span>` +
  `${renderEngineDownload(finding)}</div>`;
