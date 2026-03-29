"use strict";

import { formatHumanSize } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type { PcapClassicParseResult } from "../../analyzers/pcap/types.js";
import { renderPayloadDerivedEthernetSummary } from "../capture/ethernet-summary.js";
import { renderIssues } from "../capture/issues.js";
import { renderPacketSummary } from "../capture/packet-summary.js";

export function renderPcap(parsed: PcapClassicParseResult | null | unknown): string {
  const data = parsed as PcapClassicParseResult | null;
  if (!data) return "";

  const out: string[] = [];
  const header = data.header;

  out.push("<h3>PCAP capture file</h3>");
  out.push("<h4>Global header</h4><dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(data.fileSize))));
  out.push(
    renderDefinitionRow(
      "Endianness",
      escapeHtml(header.littleEndian ? "Little-endian" : "Big-endian")
    )
  );
  out.push(
    renderDefinitionRow("Timestamp resolution", escapeHtml(header.timestampResolution))
  );
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
    renderDefinitionRow(
      "Sigfigs",
      header.sigfigs != null ? escapeHtml(`${header.sigfigs}`) : "Unknown"
    )
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
  renderPacketSummary(data.packets, out);
  renderPayloadDerivedEthernetSummary(data, out);
  out.push(renderIssues(data.issues));
  return out.join("");
}
