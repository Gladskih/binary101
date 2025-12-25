"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import type { PcapParseResult } from "../../analyzers/pcap/types.js";

const renderIssues = (issues: string[] | null | undefined): string => {
  if (!issues || issues.length === 0) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Issues</h4><ul class="issueList">${items}</ul>`;
};

const formatTimestampSeconds = (seconds: number | null | undefined): string => {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds <= 0) return "-";
  const iso = new Date(seconds * 1000).toISOString();
  const rounded = Math.round(seconds * 1_000_000) / 1_000_000;
  return `${escapeHtml(iso)} (${escapeHtml(`${rounded}`)} s)`;
};

const formatDurationSeconds = (seconds: number | null | undefined): string => {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return "Unknown";
  if (seconds < 0.001) return `${Math.round(seconds * 1_000_000)} µs`;
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 10) return `${Math.round(seconds * 1000) / 1000} s`;
  if (seconds < 600) return `${Math.round(seconds * 10) / 10} s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = Math.round(seconds - minutes * 60);
  return `${minutes} min ${remaining} s`;
};

const describeEtherType = (etherType: number): string => {
  if (etherType === 0x0800) return "IPv4";
  if (etherType === 0x86dd) return "IPv6";
  if (etherType === 0x0806) return "ARP";
  if (etherType === 0x8100) return "802.1Q VLAN";
  if (etherType === 0x88a8) return "802.1ad QinQ";
  return "EtherType";
};

const describeIpProtocol = (protocol: number): string => {
  if (protocol === 1) return "ICMP";
  if (protocol === 2) return "IGMP";
  if (protocol === 6) return "TCP";
  if (protocol === 17) return "UDP";
  if (protocol === 41) return "IPv6";
  if (protocol === 47) return "GRE";
  if (protocol === 50) return "ESP";
  if (protocol === 51) return "AH";
  if (protocol === 58) return "ICMPv6";
  return "Protocol";
};

const renderCountTable = (
  title: string,
  items: Array<{ key: number; name: string; count: number }>,
  keyHeader: string
): string => {
  if (!items || items.length === 0) return "";
  const rows = items
    .map(item => {
      const hex = toHex32(item.key, 4);
      return `<tr><td>${escapeHtml(hex)}</td><td>${escapeHtml(item.name)}</td><td>${escapeHtml(
        `${item.count}`
      )}</td></tr>`;
    })
    .join("");
  return (
    `<h5>${escapeHtml(title)}</h5>` +
    '<table class="byteView"><thead><tr>' +
    `<th>${escapeHtml(keyHeader)}</th><th>Name</th><th>Count</th>` +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
};

const toTopCounts = (
  map: Map<number, number>,
  nameFn: (key: number) => string,
  limit: number
): Array<{ key: number; name: string; count: number }> => {
  const items = [...map.entries()].map(([key, count]) => ({ key, name: nameFn(key), count }));
  items.sort((a, b) => (b.count !== a.count ? b.count - a.count : a.key - b.key));
  return items.slice(0, Math.max(0, limit));
};

export function renderPcap(parsed: PcapParseResult | null | unknown): string {
  const data = parsed as PcapParseResult | null;
  if (!data) return "";

  const header = data.header;
  const packets = data.packets;
  const out: string[] = [];

  out.push("<h3>PCAP capture file</h3>");

  out.push("<h4>Global header</h4><dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(data.fileSize))));
  out.push(renderDefinitionRow("Endianness", escapeHtml(header.littleEndian ? "Little-endian" : "Big-endian")));
  out.push(renderDefinitionRow("Timestamp resolution", escapeHtml(header.timestampResolution)));
  out.push(
    renderDefinitionRow(
      "Version",
      header.versionMajor != null && header.versionMinor != null
        ? escapeHtml(`${header.versionMajor}.${header.versionMinor}`)
        : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Time zone offset (thiszone)",
      header.thiszone != null ? escapeHtml(`${header.thiszone}`) : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow("Sigfigs", header.sigfigs != null ? escapeHtml(`${header.sigfigs}`) : "Unknown")
  );
  out.push(
    renderDefinitionRow(
      "Snaplen",
      header.snaplen != null ? escapeHtml(formatHumanSize(header.snaplen)) : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Link-layer type",
      header.network != null
        ? escapeHtml(`${header.network} (${header.networkName || "Unknown"})`)
        : "Unknown"
    )
  );
  out.push("</dl>");

  out.push("<h4>Packets</h4><dl>");
  out.push(renderDefinitionRow("Total packets", escapeHtml(`${packets.totalPackets}`)));
  out.push(renderDefinitionRow("Total captured bytes", escapeHtml(formatHumanSize(packets.totalCapturedBytes))));
  out.push(renderDefinitionRow("Total original bytes", escapeHtml(formatHumanSize(packets.totalOriginalBytes))));
  out.push(
    renderDefinitionRow(
      "Capture length (min/avg/max)",
      packets.capturedLengthMin != null && packets.capturedLengthMax != null && packets.capturedLengthAverage != null
        ? escapeHtml(`${packets.capturedLengthMin} / ${packets.capturedLengthAverage} / ${packets.capturedLengthMax}`)
        : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Original length (min/avg/max)",
      packets.originalLengthMin != null && packets.originalLengthMax != null && packets.originalLengthAverage != null
        ? escapeHtml(`${packets.originalLengthMin} / ${packets.originalLengthAverage} / ${packets.originalLengthMax}`)
        : "Unknown"
    )
  );
  out.push(renderDefinitionRow("Capture-truncated packets", escapeHtml(`${packets.truncatedPackets}`)));
  out.push(renderDefinitionRow("File truncated", escapeHtml(packets.truncatedFile ? "Yes" : "No")));

  if (packets.timestampMinSeconds != null || packets.timestampMaxSeconds != null) {
    out.push(renderDefinitionRow("Time start", formatTimestampSeconds(packets.timestampMinSeconds)));
    out.push(renderDefinitionRow("Time end", formatTimestampSeconds(packets.timestampMaxSeconds)));
    const duration =
      packets.timestampMinSeconds != null && packets.timestampMaxSeconds != null
        ? packets.timestampMaxSeconds - packets.timestampMinSeconds
        : null;
    out.push(renderDefinitionRow("Time span", escapeHtml(formatDurationSeconds(duration))));
    out.push(renderDefinitionRow("Out-of-order timestamps", escapeHtml(`${packets.outOfOrderTimestamps}`)));
  }
  out.push("</dl>");

  const eth = data.linkLayer?.ethernet;
  if (eth) {
    out.push("<h4>Ethernet</h4><dl>");
    out.push(renderDefinitionRow("Frames parsed", escapeHtml(`${eth.framesParsed}`)));
    out.push(renderDefinitionRow("VLAN tagged frames", escapeHtml(`${eth.vlanTaggedFrames}`)));
    out.push(renderDefinitionRow("Short frames (sampled)", escapeHtml(`${eth.shortFrames}`)));
    out.push("</dl>");

    const topEtherTypes = toTopCounts(eth.etherTypes, describeEtherType, 20);
    const topProtocols = toTopCounts(eth.ipProtocols, describeIpProtocol, 20);
    out.push(renderCountTable("EtherTypes (top 20)", topEtherTypes, "EtherType"));
    out.push(renderCountTable("IP protocols (top 20)", topProtocols, "Protocol"));
  }

  out.push(renderIssues(data.issues));
  return out.join("");
}
