"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLoadConfigDirectory } from "../../analyzers/pe/load-config.js";
import { collectLoadConfigWarnings } from "../../analyzers/pe/load-config-warnings.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("collectLoadConfigWarnings reports tables that do not fit in file/image bounds", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  const lcRva = 0x80;

  dv.setUint32(lcRva + 0x00, 0xc0, true); // Size
  dv.setUint32(lcRva + 0x50, 0x1f0, true); // GuardCFFunctionTable
  dv.setUint32(lcRva + 0x54, 4, true); // GuardCFFunctionCount

  const file = new MockFile(bytes, "loadcfg-warn.bin");
  const lc = expectDefined(
    await parseLoadConfigDirectory(
      file,
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0xc0 }],
      value => value,
      () => {},
      false
    )
  );

  assert.equal(lc.GuardCFFunctionCount, 4);
  const warnings = collectLoadConfigWarnings(file.size, value => value, 0x400000, 0x200, lc);
  assert.ok(warnings.some(w => w.includes("GuardCFFunctionTable")));
});
