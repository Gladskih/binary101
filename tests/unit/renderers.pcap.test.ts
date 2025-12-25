"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parsePcap } from "../../analyzers/pcap/index.js";
import { renderPcap } from "../../renderers/pcap/index.js";
import { createPcapFile } from "../fixtures/pcap-fixtures.js";
import { MockFile } from "../helpers/mock-file.js";

void test("renderPcap renders global header and packet summary", async () => {
  const parsed = await parsePcap(createPcapFile());
  assert.ok(parsed);
  const html = renderPcap(parsed);
  assert.match(html, /PCAP/i);
  assert.match(html, /Global header/i);
  assert.match(html, /Packets/i);
  assert.match(html, /Ethernet/i);
});

void test("renderPcap renders issues and omits Ethernet when link type is unknown", async () => {
  const bytes = new Uint8Array(4);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 0xa1b2c3d4, true);
  const parsed = await parsePcap(new MockFile(bytes, "tiny.pcap"));
  assert.ok(parsed);
  const html = renderPcap(parsed);
  assert.match(html, /Issues/i);
  assert.doesNotMatch(html, /Ethernet/i);
});
