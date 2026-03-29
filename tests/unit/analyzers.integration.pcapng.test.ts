"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseForUi } from "../../analyzers/index.js";
import { createPcapNgFile } from "../fixtures/pcapng-fixtures.js";

void test("parseForUi parses PCAP-NG capture files", async () => {
  const { analyzer, parsed } = await parseForUi(createPcapNgFile());

  assert.strictEqual(analyzer, "pcapng");
  assert.ok(parsed);
  assert.strictEqual(parsed.format, "pcapng");
  assert.strictEqual(parsed.sections.length, 1);
  assert.strictEqual(parsed.interfaces.length, 2);
  assert.strictEqual(parsed.packets.totalPackets, 4);
});
