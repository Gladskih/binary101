"use strict";

import { toHex32 } from "../../binary-utils.js";
import {
  ETHERTYPE_ARP,
  ETHERTYPE_IEEE8021AD,
  ETHERTYPE_IEEE8021Q,
  ETHERTYPE_IPV4,
  ETHERTYPE_IPV6,
  IP_PROTOCOL_AH,
  IP_PROTOCOL_ESP,
  IP_PROTOCOL_GRE,
  IP_PROTOCOL_ICMP,
  IP_PROTOCOL_ICMPV6,
  IP_PROTOCOL_IGMP,
  IP_PROTOCOL_IPV6,
  IP_PROTOCOL_TCP,
  IP_PROTOCOL_UDP
} from "../../analyzers/capture/payload-analysis.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type { PcapLinkLayerSummary } from "../../analyzers/capture/types.js";

// EtherType values come from the IANA IEEE 802 Numbers registry.
// Source: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
const describeEtherType = (etherType: number): string => {
  if (etherType === ETHERTYPE_IPV4) return "IPv4";
  if (etherType === ETHERTYPE_IPV6) return "IPv6";
  if (etherType === ETHERTYPE_ARP) return "ARP";
  if (etherType === ETHERTYPE_IEEE8021Q) return "802.1Q VLAN";
  if (etherType === ETHERTYPE_IEEE8021AD) return "802.1ad QinQ";
  return "EtherType";
};

// IP protocol numbers come from the IANA Protocol Numbers registry.
// Source: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
const describeIpProtocol = (protocol: number): string => {
  if (protocol === IP_PROTOCOL_ICMP) return "ICMP";
  if (protocol === IP_PROTOCOL_IGMP) return "IGMP";
  if (protocol === IP_PROTOCOL_TCP) return "TCP";
  if (protocol === IP_PROTOCOL_UDP) return "UDP";
  if (protocol === IP_PROTOCOL_IPV6) return "IPv6";
  if (protocol === IP_PROTOCOL_GRE) return "GRE";
  if (protocol === IP_PROTOCOL_ESP) return "ESP";
  if (protocol === IP_PROTOCOL_AH) return "AH";
  if (protocol === IP_PROTOCOL_ICMPV6) return "ICMPv6";
  return "Protocol";
};

const renderCountTable = (
  title: string,
  items: Array<{ key: number; name: string; count: number }>,
  keyHeader: string
): string => {
  if (items.length === 0) return "";

  const rows = items
    .map(item => {
      const hex = toHex32(item.key, 4); // EtherType is a 16-bit field, so four hex digits are enough.
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

const toSortedCounts = (
  counts: Map<number, number>,
  describeName: (key: number) => string
): Array<{ key: number; name: string; count: number }> => {
  const items = [...counts.entries()].map(([key, count]) => ({
    key,
    name: describeName(key),
    count
  }));
  items.sort((left, right) =>
    right.count !== left.count ? right.count - left.count : left.key - right.key
  );
  return items;
};

export const renderPayloadDerivedEthernetSummary = (
  data: { linkLayer: PcapLinkLayerSummary | null },
  out: string[]
): void => {
  const ethernet = data.linkLayer?.ethernet;
  if (!ethernet) return;

  out.push("<h4>Payload-Derived Ethernet Summary</h4>");
  out.push(
    '<div class="smallNote dim">Derived from captured packet bytes, not from pcap/pcapng container fields.</div>'
  );
  out.push("<dl>");
  out.push(renderDefinitionRow("Frames parsed", escapeHtml(`${ethernet.framesParsed}`)));
  out.push(renderDefinitionRow("VLAN tagged frames", escapeHtml(`${ethernet.vlanTaggedFrames}`)));
  out.push(renderDefinitionRow("Short frames", escapeHtml(`${ethernet.shortFrames}`)));
  out.push("</dl>");
  out.push(
    renderCountTable(
      "EtherTypes",
      toSortedCounts(ethernet.etherTypes, describeEtherType),
      "EtherType"
    )
  );
  out.push(
    renderCountTable(
      "IP protocols",
      toSortedCounts(ethernet.ipProtocols, describeIpProtocol),
      "Protocol"
    )
  );
};
