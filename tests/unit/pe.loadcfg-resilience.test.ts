"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLoadConfigDirectory } from "../../analyzers/pe/load-config.js";
import { MockFile } from "../helpers/mock-file.js";

void test("parseLoadConfigDirectory returns null instead of throwing on a truncated mapped header", async () => {
  const bytes = new Uint8Array(0x18).fill(0);
  const dv = new DataView(bytes.buffer);
  const loadConfigRva = 0x10;
  dv.setUint32(loadConfigRva + 0, 0x40, true);
  dv.setUint32(loadConfigRva + 4, 0x12345678, true);

  const parse = (): Promise<Awaited<ReturnType<typeof parseLoadConfigDirectory>>> =>
    parseLoadConfigDirectory(
      new MockFile(bytes, "loadcfg-truncated.bin"),
      [{ name: "LOAD_CONFIG", rva: loadConfigRva, size: 0x40 }],
      value => value,
      () => {},
      false
    );

  await assert.doesNotReject(parse);
  assert.equal(await parse(), null);
});
