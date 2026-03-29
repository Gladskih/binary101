"use strict";

import { MockFile } from "../helpers/mock-file.js";
import {
  concatParts,
  makeCustomBlock,
  makeDecryptionSecretsBlock,
  makeEnhancedPacketBlock,
  makeEthernetFrame,
  makeInterfaceDescription,
  makeInterfaceStatisticsBlock,
  makeIpv4Header,
  makeIpv6Header,
  makeNameResolutionBlock,
  makePacketBlock,
  makeSectionHeader,
  makeSimplePacketBlock
} from "./pcapng-builder.js";

export const createPcapNgFile = (): MockFile => {
  const littleEndian = true;
  const ipv4Tcp = makeEthernetFrame(0x0800, makeIpv4Header(6));
  const ipv6Udp = makeEthernetFrame(0x86dd, makeIpv6Header(17));
  const arp = makeEthernetFrame(0x0806, new Uint8Array(28).fill(0));
  const bytes = concatParts([
    makeSectionHeader({ littleEndian, hardware: "x86 workstation", os: "Windows 11", userAppl: "binary101" }),
    makeInterfaceDescription({
      littleEndian,
      linkType: 1,
      snaplen: 65535,
      name: "eth0",
      description: "Ethernet",
      tsresol: 6,
      hardware: "Intel NIC"
    }),
    makeInterfaceDescription({
      littleEndian,
      linkType: 1,
      snaplen: 96,
      name: "wlan0",
      description: "Wi-Fi",
      tsresol: 6,
      tsoffsetSeconds: 2n,
      filter: "tcp port 443",
      os: "Remote Linux"
    }),
    makeEnhancedPacketBlock({
      littleEndian,
      interfaceId: 0,
      timestamp: 1_700_000_000_123_456n,
      payload: ipv4Tcp,
      originalLength: ipv4Tcp.length + 20,
      dropCount: 3n
    }),
    makeEnhancedPacketBlock({
      littleEndian,
      interfaceId: 1,
      timestamp: 1_700_000_001_000_000n,
      payload: ipv6Udp,
      originalLength: ipv6Udp.length,
      dropCount: 5n
    }),
    makeSimplePacketBlock({ littleEndian, payload: arp, originalLength: arp.length }),
    makePacketBlock({
      littleEndian,
      interfaceId: 1,
      dropsCount: 2,
      timestamp: 1_699_999_999_000_000n,
      payload: arp,
      originalLength: arp.length
    }),
    makeNameResolutionBlock(littleEndian),
    makeInterfaceStatisticsBlock({
      littleEndian,
      interfaceId: 0,
      timestamp: 1_700_000_002_000_000n,
      captureStart: 1_700_000_000_000_000n,
      captureEnd: 1_700_000_002_000_000n,
      receivedPackets: 4n,
      droppedByInterface: 1n,
      deliveredToUser: 3n
    }),
    makeDecryptionSecretsBlock(littleEndian),
    makeCustomBlock(littleEndian)
  ]);
  return new MockFile(bytes, "sample.pcapng", "application/x-pcapng");
};

export const createPcapNgBigEndianFile = (): MockFile => {
  const littleEndian = false;
  const ipv4Udp = makeEthernetFrame(0x0800, makeIpv4Header(17));
  const bytes = concatParts([
    makeSectionHeader({ littleEndian, hardware: "big-endian host", userAppl: "binary101" }),
    makeInterfaceDescription({ littleEndian, linkType: 1, snaplen: 65535, name: "en0", tsresol: 6 }),
    makeEnhancedPacketBlock({
      littleEndian,
      interfaceId: 0,
      timestamp: 1_700_000_100_000_000n,
      payload: ipv4Udp,
      originalLength: ipv4Udp.length
    })
  ]);
  return new MockFile(bytes, "sample-be.pcapng", "application/x-pcapng");
};

export const createPcapNgMissingInterfaceFile = (): MockFile => {
  const littleEndian = true;
  const payload = makeEthernetFrame(0x0800, makeIpv4Header(6));
  const bytes = concatParts([
    makeSectionHeader({ littleEndian }),
    makeEnhancedPacketBlock({
      littleEndian,
      interfaceId: 7,
      timestamp: 1_700_000_000_000_000n,
      payload,
      originalLength: payload.length
    })
  ]);
  return new MockFile(bytes, "missing-interface.pcapng", "application/x-pcapng");
};

export const createTruncatedPcapNgFile = (): MockFile => {
  const source = createPcapNgFile();
  return new MockFile(source.data.subarray(0, source.data.length - 6), "truncated.pcapng", "application/x-pcapng");
};
