import assert from "node:assert/strict";
import { test } from "node:test";
import { locateNativeAotGcInfo, locateReadyToRunGcInfo } from
  "../../../../../../analyzers/pe/exception/amd64/managed-gc-locations.js";
import { managedGcContainerFixture } from "../../../../../helpers/managed-gc-container-fixture.js";

void test("locates aligned R2R GC info and unaligned NativeAOT root tails", async () => {
  const source = managedGcContainerFixture();
  source.bytes.set([1, 0, 1, 0], 64);

  assert.equal(await locateReadyToRunGcInfo(source.reader(), source.mapper, 64), 76);
  assert.equal(await locateNativeAotGcInfo(source.reader(), source.mapper, 64), 71);
  source.bytes[64] = 9; // UNW_FLAG_EHANDLER aligns the personality DWORD.
  source.bytes[76] = 0x14; // NativeAOT associated-data and EH relative pointers.
  assert.equal(await locateNativeAotGcInfo(source.reader(), source.mapper, 64), 85);
});

void test("rejects missing optional pointers rather than jumping across unmapped bytes", async () => {
  const source = managedGcContainerFixture();
  source.bytes.set([1, 0, 0, 0, 0x14], 248);

  await assert.rejects(locateNativeAotGcInfo(source.reader(), source.mapper, 248), /truncated/);
  source.bytes.set([1, 0, 255, 0], 248);
  await assert.rejects(locateReadyToRunGcInfo(source.reader(), source.mapper, 248), /truncated/);
});

void test("rejects malformed unwind headers and leaves funclets bound to their root map", async () => {
  const source = managedGcContainerFixture();
  source.bytes.set([1, 0, 0, 0, 1], 64);

  assert.equal(await locateNativeAotGcInfo(source.reader(), source.mapper, 64), null);
  source.bytes[68] = 0xe0;
  await assert.rejects(locateNativeAotGcInfo(source.reader(), source.mapper, 64), /reserved/);
  source.bytes[64] = 3;
  await assert.rejects(locateReadyToRunGcInfo(source.reader(), source.mapper, 64), /version/);
  source.bytes[64] = 33;
  await assert.rejects(locateReadyToRunGcInfo(source.reader(), source.mapper, 64), /chained/);
  await assert.rejects(locateReadyToRunGcInfo(source.reader(), source.mapper, 255), /truncated/);
  source.bytes.set([1, 0, 0, 0], 252);
  await assert.rejects(locateNativeAotGcInfo(source.reader(), source.mapper, 252), /truncated/);
});

void test("rejects holes in unwind codes even when the following GC tail is mapped", async () => {
  const source = managedGcContainerFixture();
  source.bytes.set([1, 0, 4, 0], 64);

  await assert.rejects(locateNativeAotGcInfo(source.reader(),
    rva => rva === 68 ? null : rva, 64), /codes or personality are truncated/);
});
