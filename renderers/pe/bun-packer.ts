"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { escapeHtml, renderFlagChips, renderOptionChips } from "../../html-utils.js";
import type { PeBunPackerFinding } from "../../analyzers/pe/packers/index.js";

// Bun StandaloneModuleGraph.Flags currently occupies the low four bits.
// https://github.com/oven-sh/bun/blob/main/src/standalone_graph/StandaloneModuleGraph.zig
const BUN_FLAGS: Array<[number, string, string]> = [
  [0x01, "Disable env files", "Do not load the default environment files"],
  [0x02, "Disable bunfig", "Do not automatically load bunfig.toml"],
  [0x04, "Disable tsconfig", "Do not automatically load tsconfig.json"],
  [0x08, "Disable package.json", "Do not automatically load package.json"]
];

const BUN_STORAGE_OPTIONS: Array<[number, string, string]> = [
  [0, "Length-prefixed PE section", "An 8-byte little-endian payload length precedes the graph"],
  [1, "PE section virtual data", "The payload occupies the meaningful virtual extent of the section"]
];

const formatBunBytes = (size: number): string =>
  size < 1024 ? `${size} bytes` : humanSize(size);

const renderBunRow = (
  label: string,
  valueHtml: string,
  meaning: string,
  valueClass = ""
): string =>
  `<tr><th scope="row" class="peBunTable__field">${escapeHtml(label)}</th>` +
  `<td${valueClass ? ` class="${valueClass}"` : ""}>${valueHtml}</td>` +
  `<td class="smallNote pePackerFinding__meaning">${escapeHtml(meaning)}</td></tr>`;

const renderBunRangeRows = (finding: PeBunPackerFinding): string =>
  renderBunRow(".bun raw start", hex(finding.sectionStart, 8),
    "First raw file byte occupied by the .bun section.", "peNumeric") +
  renderBunRow(".bun raw end", hex(finding.sectionStart + finding.sectionSize, 8),
    "Exclusive end of the .bun section's raw file data.", "peNumeric") +
  renderBunRow(".bun raw size", formatBunBytes(finding.sectionSize),
    "Raw file size declared by the PE section table.", "peNumeric") +
  renderBunRow("Payload start", hex(finding.payloadStart, 8),
    "First byte of the validated standalone module graph.", "peNumeric") +
  renderBunRow("Payload end", hex(finding.payloadStart + finding.payloadSize, 8),
    "Exclusive end of the validated standalone module graph.", "peNumeric") +
  renderBunRow("Payload size", formatBunBytes(finding.payloadSize),
    "Validated standalone module-graph payload size.", "peNumeric");

const renderBunMetadataRows = (finding: PeBunPackerFinding): string => {
  const metadata = finding.offsetMetadata;
  if (!metadata) return "";
  return renderBunRow("Graph byte count", formatBunBytes(metadata.byteCount),
    "Payload bytes declared by Bun's embedded module graph.", "peNumeric") +
    renderBunRow("Entry point id", String(metadata.entryPointId),
      "Identifier of the embedded module selected as the program entry point.", "peNumeric") +
    renderBunRow("Module-list bytes", formatBunBytes(metadata.moduleListBytes),
      "Encoded byte length of the embedded module list.", "peNumeric") +
    renderBunRow("Compile argv bytes", formatBunBytes(metadata.compileArgvBytes),
      "Encoded byte length of arguments captured by Bun's compiler.", "peNumeric") +
    renderBunRow("Flags", renderFlagChips(metadata.flags, BUN_FLAGS),
      "Standalone compile options stored in Bun's Flags bitmask.");
};

export const renderBunFindingDetails = (finding: PeBunPackerFinding): string =>
  `<div class="tableWrap"><table class="table peBunTable pePackerFinding__details">` +
  `<thead><tr><th>Field</th><th>Value</th><th>Meaning</th></tr></thead><tbody>` +
  renderBunRangeRows(finding) +
  renderBunRow(
    "Storage",
    renderOptionChips(finding.storage === "length-prefixed" ? 0 : 1, BUN_STORAGE_OPTIONS),
    "How the embedded Bun payload is stored in the PE section."
  ) +
  renderBunMetadataRows(finding) +
  `</tbody></table></div>`;
