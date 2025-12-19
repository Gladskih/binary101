"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLoadConfigDirectory } from "../../analyzers/pe/load-config.js";
import { collectLoadConfigWarnings } from "../../analyzers/pe/load-config-warnings.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("parseLoadConfigDirectory reads VolatileMetadataPointer for x64", async () => {
  const lcRva = 0x20;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(lcRva + 0x00, 0x148, true); // Size
  dv.setBigUint64(lcRva + 0x100, 0x14001ac34n, true);

  const lc = expectDefined(
    await parseLoadConfigDirectory(
      new MockFile(bytes, "loadcfg-volatile64.bin"),
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0x148 }],
      value => value,
      () => {},
      true
    )
  );
  assert.equal(lc.VolatileMetadataPointer, 0x14001ac34);
});

void test("parseLoadConfigDirectory reads VolatileMetadataPointer for x86", async () => {
  const lcRva = 0x20;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(lcRva + 0x00, 0xc4, true); // Size
  dv.setUint32(lcRva + 0xa0, 0x12345678, true);

  const lc = expectDefined(
    await parseLoadConfigDirectory(
      new MockFile(bytes, "loadcfg-volatile32.bin"),
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0xc4 }],
      value => value,
      () => {},
      false
    )
  );
  assert.equal(lc.VolatileMetadataPointer, 0x12345678);
});

void test("collectLoadConfigWarnings warns when VolatileMetadataPointer does not map to file data", async () => {
  const lcRva = 0x20;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(lcRva + 0x00, 0x148, true); // Size
  dv.setBigUint64(lcRva + 0x100, 0x500n, true);

  const file = new MockFile(bytes, "loadcfg-volatile-warn.bin");
  const lc = expectDefined(
    await parseLoadConfigDirectory(
      file,
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0x148 }],
      value => value,
      () => {},
      true
    )
  );

  const warnings = collectLoadConfigWarnings(file.size, value => value, 0, 0x1000, lc);
  assert.ok(warnings.some(w => w.includes("VolatileMetadataPointer") && w.includes("does not map to file data")));
});

