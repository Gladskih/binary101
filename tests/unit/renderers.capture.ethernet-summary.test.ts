"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import type { PcapLinkLayerSummary } from "../../analyzers/capture/types.js";
import { renderPayloadDerivedEthernetSummary } from "../../renderers/capture/ethernet-summary.js";

void test("renderPayloadDerivedEthernetSummary renders derived Ethernet counters", () => {
  const linkLayer: PcapLinkLayerSummary = {
    ethernet: {
      framesParsed: 4,
      vlanTaggedFrames: 1,
      shortFrames: 0,
      etherTypes: new Map([
        [0x0800, 3],
        [0x86dd, 1]
      ]),
      ipProtocols: new Map([
        [6, 2],
        [17, 1]
      ])
    }
  };

  const out: string[] = [];
  renderPayloadDerivedEthernetSummary({ linkLayer }, out);
  const html = out.join("");

  assert.match(html, /Payload-Derived Ethernet Summary/);
  assert.match(html, /Derived from captured packet bytes/);
  assert.match(html, /Frames parsed/);
  assert.match(html, /VLAN tagged frames/);
  assert.match(html, /IPv4/);
  assert.match(html, /TCP/);
});
