"use strict";

import { formatHumanSize } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type {
  PcapNgBlockSummary,
  PcapNgInterfaceSummary,
  PcapNgNameResolutionSummary,
  PcapNgParseResult
} from "../../analyzers/pcapng/types.js";
import { renderPayloadDerivedEthernetSummary } from "../capture/ethernet-summary.js";
import { renderIssues } from "../capture/issues.js";
import { renderPacketSummary } from "../capture/packet-summary.js";

const renderPcapNgBlocks = (blocks: PcapNgBlockSummary): string =>
  "<h4>Blocks</h4><dl>" +
  renderDefinitionRow("Total blocks", escapeHtml(`${blocks.totalBlocks}`)) +
  renderDefinitionRow(
    "Interface descriptions",
    escapeHtml(`${blocks.interfaceDescriptionBlocks}`)
  ) +
  renderDefinitionRow("Enhanced packet blocks", escapeHtml(`${blocks.enhancedPacketBlocks}`)) +
  renderDefinitionRow("Simple packet blocks", escapeHtml(`${blocks.simplePacketBlocks}`)) +
  renderDefinitionRow("Legacy packet blocks", escapeHtml(`${blocks.packetBlocks}`)) +
  renderDefinitionRow(
    "Name resolution blocks",
    escapeHtml(`${blocks.nameResolutionBlocks}`)
  ) +
  renderDefinitionRow(
    "Interface statistics blocks",
    escapeHtml(`${blocks.interfaceStatisticsBlocks}`)
  ) +
  renderDefinitionRow(
    "Decryption secrets blocks",
    escapeHtml(`${blocks.decryptionSecretsBlocks}`)
  ) +
  renderDefinitionRow("Custom blocks", escapeHtml(`${blocks.customBlocks}`)) +
  renderDefinitionRow("Unknown blocks", escapeHtml(`${blocks.unknownBlocks}`)) +
  "</dl>";

const renderPcapNgNameResolution = (nameResolution: PcapNgNameResolutionSummary): string =>
  "<h4>Name Resolution</h4><dl>" +
  renderDefinitionRow("IPv4 records", escapeHtml(`${nameResolution.ipv4Records}`)) +
  renderDefinitionRow("IPv6 records", escapeHtml(`${nameResolution.ipv6Records}`)) +
  renderDefinitionRow("Other records", escapeHtml(`${nameResolution.otherRecords}`)) +
  renderDefinitionRow(
    "Missing end markers",
    escapeHtml(`${nameResolution.missingEndMarkers}`)
  ) +
  "</dl>";

const renderPcapNgSections = (data: PcapNgParseResult): string => {
  if (data.sections.length === 0) return "";

  const rows = data.sections
    .map(section => {
      const sectionLength =
        section.sectionLength == null ? "Unspecified" : section.sectionLength.toString();

      return (
        "<tr>" +
        `<td>${escapeHtml(`${section.index}`)}</td>` +
        `<td>${escapeHtml(section.littleEndian ? "Little-endian" : "Big-endian")}</td>` +
        `<td>${escapeHtml(
          section.versionMajor != null && section.versionMinor != null
            ? `${section.versionMajor}.${section.versionMinor}`
            : "Unknown"
        )}</td>` +
        `<td>${escapeHtml(sectionLength)}</td>` +
        `<td>${escapeHtml(section.hardware || "-")}</td>` +
        `<td>${escapeHtml(section.os || "-")}</td>` +
        `<td>${escapeHtml(section.userAppl || "-")}</td>` +
        "</tr>"
      );
    })
    .join("");

  return (
    "<h4>Sections</h4>" +
    '<table class="byteView"><thead><tr>' +
    "<th>Section</th><th>Endianness</th><th>Version</th><th>Length</th>" +
    "<th>Hardware</th><th>OS</th><th>Application</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
};

const renderPcapNgInterfaces = (interfaces: PcapNgInterfaceSummary[]): string => {
  if (interfaces.length === 0) return "";

  const rows = interfaces
    .map(interfaceInfo => {
      const stats = interfaceInfo.statistics;
      const liveStats =
        stats &&
        (stats.receivedPackets != null ||
          stats.droppedByInterface != null ||
          stats.deliveredToUser != null)
          ? `${stats.receivedPackets?.toString() || "-"} / ${
              stats.droppedByInterface?.toString() || "-"
            } / ${stats.deliveredToUser?.toString() || "-"}`
          : "-";

      return (
        "<tr>" +
        `<td>${escapeHtml(`${interfaceInfo.sectionIndex}`)}</td>` +
        `<td>${escapeHtml(`${interfaceInfo.interfaceId}`)}</td>` +
        `<td>${escapeHtml(`${interfaceInfo.linkType} (${interfaceInfo.linkTypeName})`)}</td>` +
        `<td>${escapeHtml(interfaceInfo.name || "-")}</td>` +
        `<td>${escapeHtml(interfaceInfo.description || "-")}</td>` +
        `<td>${escapeHtml(formatHumanSize(interfaceInfo.snaplen))}</td>` +
        `<td>${escapeHtml(interfaceInfo.timestampResolution)}</td>` +
        `<td>${escapeHtml(interfaceInfo.timestampOffsetSeconds?.toString() || "-")}</td>` +
        `<td>${escapeHtml(`${interfaceInfo.packets.totalPackets}`)}</td>` +
        `<td>${escapeHtml(interfaceInfo.observedDropCount?.toString() || "-")}</td>` +
        `<td>${escapeHtml(liveStats)}</td>` +
        "</tr>"
      );
    })
    .join("");

  return (
    "<h4>Interfaces</h4>" +
    '<table class="byteView"><thead><tr>' +
    "<th>Section</th><th>ID</th><th>Link type</th><th>Name</th><th>Description</th>" +
    "<th>Snaplen</th><th>Timestamp resolution</th><th>Timestamp offset</th><th>Packets</th>" +
    "<th>Observed drops</th><th>ISB recv/drop/usr</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
};

export function renderPcapNg(parsed: PcapNgParseResult | null | unknown): string {
  const data = parsed as PcapNgParseResult | null;
  if (!data) return "";

  const out: string[] = [];
  out.push("<h3>PCAP-NG capture file</h3>");
  out.push("<h4>Overview</h4><dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(data.fileSize))));
  out.push(renderDefinitionRow("Sections", escapeHtml(`${data.sections.length}`)));
  out.push(renderDefinitionRow("Interfaces", escapeHtml(`${data.interfaces.length}`)));
  out.push("</dl>");
  out.push(renderPcapNgBlocks(data.blocks));
  renderPacketSummary(data.packets, out);
  if (data.blocks.nameResolutionBlocks > 0) {
    out.push(renderPcapNgNameResolution(data.nameResolution));
  }
  out.push(renderPcapNgSections(data));
  out.push(renderPcapNgInterfaces(data.interfaces));
  renderPayloadDerivedEthernetSummary(data, out);
  out.push(renderIssues(data.issues));
  return out.join("");
}
