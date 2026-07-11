"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLoadConfigDirectory32 } from "../../../../../analyzers/pe/load-config/index.js";
import { MockFile } from "../../../../helpers/mock-file.js";

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
      value => value
    );

  await assert.doesNotReject(parse);
  const parsed = await parse();
  assert.ok(parsed);
  assert.equal(parsed?.TimeDateStamp, 0x12345678);
  assert.ok(parsed?.warnings?.some(warning => warning.toLowerCase().includes("truncated")));
});

void test("parseLoadConfigDirectory bounds internal Size by mapped RVA bytes", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  const loadConfigRva = 0x80;

  // Microsoft PE format, Load Configuration Directory:
  // x86 pre-reserved SEH data-directory size 64 is a compatibility version check.
  dv.setUint32(loadConfigRva + 0, 0xc0, true);
  dv.setUint32(loadConfigRva + 0x40, 0x200, true);
  dv.setUint32(loadConfigRva + 0x44, 3, true);

  const parsed = await parseLoadConfigDirectory32(
    new MockFile(bytes, "loadcfg-mapped-truncated.bin"),
    [{ name: "LOAD_CONFIG", rva: loadConfigRva, size: 0x40 }],
    value => (value >= loadConfigRva && value < loadConfigRva + 0x40 ? value : null)
  );

  assert.ok(parsed);
  assert.equal(parsed?.SEHandlerTable, 0n);
  assert.equal(parsed?.SEHandlerCount, 0);
  assert.ok(parsed?.warnings?.some(warning => warning.includes("smaller than the Size field")));
});

void test("parseLoadConfigDirectory follows adjacent RVAs across noncontiguous raw sections", async () => {
  const bytes = new Uint8Array(0xc0);
  const logical = new Uint8Array(0x40);
  const view = new DataView(logical.buffer);
  // Windows SDK IMAGE_LOAD_CONFIG_DIRECTORY32 puts GlobalFlagsClear at 0x0c and SecurityCookie at 0x3c.
  view.setUint32(0, 0x40, true);
  view.setUint32(0x0c, 0x01020304, true);
  view.setUint32(0x3c, 0x05060708, true);
  bytes.set(logical.subarray(0, 0x20), 0x10);
  bytes.set(logical.subarray(0x20), 0x80);
  const parsed = await parseLoadConfigDirectory32(
    new MockFile(bytes, "loadcfg-section-split.bin"),
    [{ name: "LOAD_CONFIG", rva: 0x1000, size: 0x40 }],
    rva => {
      if (rva >= 0x1000 && rva < 0x1020) return 0x10 + rva - 0x1000;
      if (rva >= 0x1020 && rva < 0x1040) return 0x80 + rva - 0x1020;
      return null;
    }
  );
  assert.equal(parsed?.GlobalFlagsClear, 0x01020304);
  assert.equal(parsed?.SecurityCookie, 0x05060708n);
  assert.deepEqual(parsed?.warnings, undefined);
});

void test("parseLoadConfigDirectory reports SDK extensions without an artificial size cap", async () => {
  const bytes = new Uint8Array(0x100);
  const view = new DataView(bytes.buffer);
  // This intentionally exceeds the removed 64-KiB implementation cap.
  view.setUint32(0x10, 0x1_0001, true);
  view.setUint32(0x10 + 0x3c, 0x01020304, true);
  let maximumMappedRva = 0;
  const parsed = await parseLoadConfigDirectory32(
    new MockFile(bytes, "loadcfg-future-extension.bin"),
    [{ name: "LOAD_CONFIG", rva: 0x10, size: 0x40 }],
    rva => {
      maximumMappedRva = Math.max(maximumMappedRva, rva);
      return rva;
    }
  );
  assert.equal(parsed?.SecurityCookie, 0x01020304n);
  // Windows SDK 10.0.26100.0 publishes a 0xc4-byte x86 layout, ending at RVA 0xd3 here.
  assert.equal(maximumMappedRva, 0xd3);
  assert.deepEqual(parsed?.notes, [
    "LOAD_CONFIG contains bytes beyond the 196-byte layout published by the current Windows SDK."
  ]);
});

void test("parseLoadConfigDirectory distinguishes absent and malformed directory locations", async () => {
  const file = new MockFile(new Uint8Array(0x20), "loadcfg-locations.bin");
  const absent = await parseLoadConfigDirectory32(file, [{ name: "EXPORT", rva: 1, size: 1 }], rva => rva);
  const empty = await parseLoadConfigDirectory32(
    file, [{ name: "LOAD_CONFIG", rva: 0, size: 0 }], rva => rva
  );
  const zeroRva = await parseLoadConfigDirectory32(
    file, [{ name: "LOAD_CONFIG", rva: 0, size: 4 }], rva => rva
  );
  const unmapped = await parseLoadConfigDirectory32(
    file, [{ name: "LOAD_CONFIG", rva: 0x10, size: 4 }], () => null
  );
  const pastFile = await parseLoadConfigDirectory32(
    file, [{ name: "LOAD_CONFIG", rva: 0x10, size: 4 }], () => file.size
  );
  assert.equal(absent, null);
  assert.equal(empty, null);
  assert.deepEqual(zeroRva?.warnings, ["LOAD_CONFIG has a non-zero size but RVA is 0."]);
  assert.deepEqual(unmapped?.warnings, ["LOAD_CONFIG RVA could not be mapped to a file offset."]);
  assert.deepEqual(pastFile?.warnings, ["LOAD_CONFIG starts past end of file."]);
});

void test("parseLoadConfigDirectory reports zero, short, and undersized directory data", async () => {
  const bytes = new Uint8Array(0x40);
  const file = new MockFile(bytes, "loadcfg-small.bin");
  const zeroSize = await parseLoadConfigDirectory32(
    file, [{ name: "LOAD_CONFIG", rva: 0x10, size: 0 }], rva => rva
  );
  const shortSizeField = await parseLoadConfigDirectory32(
    file, [{ name: "LOAD_CONFIG", rva: 0x10, size: 3 }], rva => rva
  );
  new DataView(bytes.buffer).setUint32(0x10, 12, true);
  const exactFixedHeader = await parseLoadConfigDirectory32(
    new MockFile(bytes), [{ name: "LOAD_CONFIG", rva: 0x10, size: 12 }], rva => rva
  );
  assert.deepEqual(zeroSize?.warnings, ["LOAD_CONFIG does not contain any readable bytes."]);
  assert.ok(shortSizeField?.warnings?.some(warning => warning.includes("truncated before the Size field")));
  assert.ok(exactFixedHeader?.warnings?.some(warning => warning.includes("Size field is smaller")));
  assert.ok(!exactFixedHeader?.warnings?.some(warning => warning.includes("fixed header fields")));
  assert.equal(exactFixedHeader?.Major, 0);
  assert.equal(exactFixedHeader?.Minor, 0);
});
