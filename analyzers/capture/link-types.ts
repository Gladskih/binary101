"use strict";

// Subset of the PCAP LinkType registry used by the current UI.
// Source: draft-ietf-opsawg-pcaplinktype-11 Section 2.2.1,
// https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcaplinktype-11
export const LINKTYPE_ETHERNET = 1;

const LINK_TYPES: Record<number, string> = {
  0: "Null/loopback",
  [LINKTYPE_ETHERNET]: "Ethernet",
  101: "Raw IP",
  105: "IEEE 802.11",
  113: "Linux cooked capture"
};

export const describeLinkType = (linkType: number): string | null => LINK_TYPES[linkType] || null;
