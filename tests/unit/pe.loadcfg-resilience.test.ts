"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLoadConfigDirectory32 } from "../../analyzers/pe/load-config/index.js";
import { MockFile } from "../helpers/mock-file.js";

void test("parseLoadConfigDirectory returns a partial result with warnings on a truncated mapped header", async () => {
  const bytes = new Uint8Array(0x18).fill(0);
  const dv = new DataView(bytes.buffer);
  const loadConfigRva = 0x10;
  // Microsoft PE format spec, Load Configuration Directory:
  // 0x40 bytes is the minimum documented header span for the legacy fixed fields we keep visible as warnings.
  dv.setUint32(loadConfigRva + 0, 0x40, true);
  dv.setUint32(loadConfigRva + 4, 0x12345678, true);

  const parse = (): Promise<Awaited<ReturnType<typeof parseLoadConfigDirectory32>>> =>
    parseLoadConfigDirectory32(
      new MockFile(bytes, "loadcfg-truncated.bin"),
      [{ name: "LOAD_CONFIG", rva: loadConfigRva, size: 0x40 }],
      value => value,
      () => {}
    );

  await assert.doesNotReject(parse);
  const parsed = await parse();
  assert.ok(parsed);
  assert.equal(parsed?.TimeDateStamp, 0x12345678);
  assert.ok(parsed?.warnings?.some(warning => warning.toLowerCase().includes("truncated")));
});
