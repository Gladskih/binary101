"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { analyzeEthernetSample, createEthernetSummary } from "../../analyzers/capture/payload-analysis.js";

void test("analyzeEthernetSample parses Ethernet, VLAN, IPv4, and IPv6 protocol summaries", () => {
  const ethernet = createEthernetSummary();

  const vlanIpv4 = new Uint8Array(18 + 20).fill(0);
  vlanIpv4[12] = 0x81;
  vlanIpv4[13] = 0x00;
  vlanIpv4[16] = 0x08;
  vlanIpv4[17] = 0x00;
  vlanIpv4[18] = 0x45;
  vlanIpv4[27] = 17;
  analyzeEthernetSample(vlanIpv4, ethernet);

  const ipv6 = new Uint8Array(14 + 40).fill(0);
  ipv6[12] = 0x86;
  ipv6[13] = 0xdd;
  ipv6[14] = 0x60;
  ipv6[20] = 58;
  analyzeEthernetSample(ipv6, ethernet);

  assert.strictEqual(ethernet.framesParsed, 2);
  assert.strictEqual(ethernet.vlanTaggedFrames, 1);
  assert.strictEqual(ethernet.etherTypes.get(0x0800), 1);
  assert.strictEqual(ethernet.etherTypes.get(0x86dd), 1);
  assert.strictEqual(ethernet.ipProtocols.get(17), 1);
  assert.strictEqual(ethernet.ipProtocols.get(58), 1);
});

void test("analyzeEthernetSample counts short and truncated frames safely", () => {
  const ethernet = createEthernetSummary();

  analyzeEthernetSample(new Uint8Array(10).fill(0), ethernet);

  const shortVlan = new Uint8Array(16).fill(0);
  shortVlan[12] = 0x81;
  shortVlan[13] = 0x00;
  analyzeEthernetSample(shortVlan, ethernet);

  analyzeEthernetSample(new Uint8Array(0), ethernet);
  analyzeEthernetSample(new Uint8Array(14).fill(0), null);

  assert.strictEqual(ethernet.shortFrames, 2);
  assert.strictEqual(ethernet.framesParsed, 0);
});
