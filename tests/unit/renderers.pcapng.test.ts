"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parsePcapNg } from "../../analyzers/pcapng/index.js";
import { renderPcapNg } from "../../renderers/pcapng/index.js";
import { createPcapNgFile } from "../fixtures/pcapng-fixtures.js";

void test("renderPcapNg renders pcapng sections and interfaces", async () => {
  const parsed = await parsePcapNg(createPcapNgFile());
  assert.ok(parsed);
  const html = renderPcapNg(parsed);
  assert.match(html, /PCAP-NG/i);
  assert.match(html, /Sections/i);
  assert.match(html, /Interfaces/i);
  assert.match(html, /Name Resolution/i);
  assert.match(html, /Timestamp offset/i);
});
