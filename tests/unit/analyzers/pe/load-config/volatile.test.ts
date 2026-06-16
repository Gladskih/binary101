"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseLoadConfigDirectory32,
  parseLoadConfigDirectory64
} from "../../../../../analyzers/pe/load-config/index.js";
import { collectLoadConfigDiagnostics } from "../../../../../analyzers/pe/load-config/warnings.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { expectDefined } from "../../../../helpers/expect-defined.js";

void test("parseLoadConfigDirectory reads VolatileMetadataPointer for x64", async () => {
  const lcRva = 0x20;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(lcRva + 0x00, 0x148, true); // Size
  dv.setBigUint64(lcRva + 0x100, 0x14001ac34n, true);

  const lc = expectDefined(
    await parseLoadConfigDirectory64(
      new MockFile(bytes, "loadcfg-volatile64.bin"),
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0x148 }],
      value => value
    )
  );
  assert.equal(lc.VolatileMetadataPointer, 0x14001ac34n);
});

void test("parseLoadConfigDirectory reads VolatileMetadataPointer for x86", async () => {
  const lcRva = 0x20;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(lcRva + 0x00, 0xc4, true); // Size
  dv.setUint32(lcRva + 0xa0, 0x12345678, true);

  const lc = expectDefined(
    await parseLoadConfigDirectory32(
      new MockFile(bytes, "loadcfg-volatile32.bin"),
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0xc4 }],
      value => value
    )
  );
  assert.equal(lc.VolatileMetadataPointer, 0x12345678n);
});

void test("collectLoadConfigDiagnostics warns when VolatileMetadataPointer maps outside file data", async () => {
  const lcRva = 0x20;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  const imageBase = 0x400000n;
  dv.setUint32(lcRva + 0x00, 0x148, true); // Size
  dv.setBigUint64(lcRva + 0x100, imageBase + 0x500n, true);

  const file = new MockFile(bytes, "loadcfg-volatile-warn.bin");
  const lc = expectDefined(
    await parseLoadConfigDirectory64(
      file,
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0x148 }],
      value => value
    )
  );

  const warnings = collectLoadConfigDiagnostics(file.size, value => value, imageBase, 0x1000, lc).warnings;
  assert.ok(warnings.some(w => w.includes("VolatileMetadataPointer") && w.includes("maps outside file data")));
});

void test("collectLoadConfigDiagnostics notes when VolatileMetadataPointer is not raw-file-backed", async () => {
  const lcRva = 0x20;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  const imageBase = 0x400000n;
  dv.setUint32(lcRva + 0x00, 0x148, true); // Size
  dv.setBigUint64(lcRva + 0x100, imageBase + 0x500n, true);

  const lc = expectDefined(
    await parseLoadConfigDirectory64(
      new MockFile(bytes, "loadcfg-volatile-note.bin"),
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0x148 }],
      value => value
    )
  );

  const diagnostics = collectLoadConfigDiagnostics(bytes.length, () => null, imageBase, 0x1000, lc);
  assert.equal(diagnostics.warnings.length, 0);
  assert.ok(diagnostics.notes.some(note =>
    note.includes("VolatileMetadataPointer") && note.includes("not backed by raw file data")
  ));
});
