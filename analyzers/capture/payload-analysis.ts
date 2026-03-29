"use strict";

import type { PcapEthernetSummary } from "./types.js";

// Ethernet II uses a 14-octet base header: 6-byte destination MAC,
// 6-byte source MAC, then the 2-byte EtherType field.
// Source: RFC 894 Section 2,
// https://www.rfc-editor.org/rfc/rfc894.html
const ETHERNET_HEADER_BYTES = 14;

// IEEE 802.1Q and 802.1ad add a 4-octet tag before the encapsulated EtherType.
// The TPID values below come from the IANA IEEE 802 Numbers registry.
// Source: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
const VLAN_TAGGED_ETHERNET_HEADER_BYTES = 18;
export const ETHERTYPE_IPV4 = 0x0800;
export const ETHERTYPE_ARP = 0x0806;
export const ETHERTYPE_IEEE8021Q = 0x8100;
export const ETHERTYPE_IPV6 = 0x86dd;
export const ETHERTYPE_IEEE8021AD = 0x88a8;

// IPv4 Version/IHL and Protocol field positions are defined in RFC 791 Section 3.1.
// Source: https://www.rfc-editor.org/rfc/rfc791.html#section-3.1
const IP_VERSION_SHIFT = 4;

// IPv6 Version and Next Header field positions are defined in RFC 8200 Section 3.
// Source: https://www.rfc-editor.org/rfc/rfc8200.html#section-3

// Protocol numbers are assigned by IANA.
// Source: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
export const IP_PROTOCOL_ICMP = 1;
export const IP_PROTOCOL_IGMP = 2;
export const IP_PROTOCOL_TCP = 6;
export const IP_PROTOCOL_UDP = 17;
export const IP_PROTOCOL_IPV6 = 41;
export const IP_PROTOCOL_GRE = 47;
export const IP_PROTOCOL_ESP = 50;
export const IP_PROTOCOL_AH = 51;
export const IP_PROTOCOL_ICMPV6 = 58;

const incrementMapCount = (map: Map<number, number>, key: number): void => {
  map.set(key, (map.get(key) || 0) + 1);
};

const readUint16be = (bytes: Uint8Array, offset: number): number | null => {
  if (offset + 2 > bytes.length) return null;
  return ((bytes[offset] ?? 0) << 8) | (bytes[offset + 1] ?? 0);
};

const parseEthernetFromSample = (
  sample: Uint8Array,
  ethernet: PcapEthernetSummary
): { etherType: number | null; etherPayloadOffset: number | null } => {
  if (sample.length < ETHERNET_HEADER_BYTES) {
    ethernet.shortFrames += 1;
    return { etherType: null, etherPayloadOffset: null };
  }
  let etherType = readUint16be(sample, 12); // EtherType is at octets 12-13 of the Ethernet II header.
  if (etherType == null) {
    ethernet.shortFrames += 1;
    return { etherType: null, etherPayloadOffset: null };
  }
  let payloadOffset = ETHERNET_HEADER_BYTES;
  if (etherType === ETHERTYPE_IEEE8021Q || etherType === ETHERTYPE_IEEE8021AD) {
    if (sample.length < VLAN_TAGGED_ETHERNET_HEADER_BYTES) {
      ethernet.shortFrames += 1;
      return { etherType: null, etherPayloadOffset: null };
    }
    ethernet.vlanTaggedFrames += 1;
    const innerType = readUint16be(sample, 16); // The encapsulated EtherType follows the 4-octet VLAN tag.
    if (innerType == null) {
      ethernet.shortFrames += 1;
      return { etherType: null, etherPayloadOffset: null };
    }
    etherType = innerType;
    payloadOffset = VLAN_TAGGED_ETHERNET_HEADER_BYTES;
  }
  incrementMapCount(ethernet.etherTypes, etherType);
  ethernet.framesParsed += 1;
  return { etherType, etherPayloadOffset: payloadOffset };
};

const parseIpProtocolFromEthernetSample = (
  sample: Uint8Array,
  etherType: number,
  etherPayloadOffset: number,
  ethernet: PcapEthernetSummary
): void => {
  if (etherType === ETHERTYPE_IPV4) {
    if (etherPayloadOffset + 10 > sample.length) return; // The IPv4 Protocol field is byte 9.
    if (((sample[etherPayloadOffset] ?? 0) >>> IP_VERSION_SHIFT) !== 4) return;
    incrementMapCount(
      ethernet.ipProtocols,
      sample[etherPayloadOffset + 9] ?? 0
    );
    return;
  }
  if (
    etherType !== ETHERTYPE_IPV6 ||
    etherPayloadOffset + 7 > sample.length // The IPv6 Next Header field is byte 6.
  ) {
    return;
  }
  if (((sample[etherPayloadOffset] ?? 0) >>> IP_VERSION_SHIFT) !== 6) return;
  incrementMapCount(
    ethernet.ipProtocols,
    sample[etherPayloadOffset + 6] ?? 0
  );
};

export const createEthernetSummary = (): PcapEthernetSummary => ({
  framesParsed: 0,
  vlanTaggedFrames: 0,
  shortFrames: 0,
  etherTypes: new Map<number, number>(),
  ipProtocols: new Map<number, number>()
});

export const analyzeEthernetSample = (
  sample: Uint8Array,
  ethernet: PcapEthernetSummary | null
): void => {
  if (!ethernet || sample.length === 0) return;
  const { etherType, etherPayloadOffset } = parseEthernetFromSample(sample, ethernet);
  if (etherType == null || etherPayloadOffset == null) return;
  parseIpProtocolFromEthernetSample(sample, etherType, etherPayloadOffset, ethernet);
};
