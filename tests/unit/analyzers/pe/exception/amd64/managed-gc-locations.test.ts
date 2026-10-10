import assert from "node:assert/strict";
import { test } from "node:test";
import { locateNativeAotGcInfo, locateReadyToRunGcInfo } from
  "../../../../../../analyzers/pe/exception/amd64/managed-gc-locations.js";
import { managedGcContainerFixture } from "../../../../../helpers/managed-gc-container-fixture.js";

void test("locates aligned R2R GC info and unaligned NativeAOT root tails", async () => {
  const source = managedGcContainerFixture();
  const { rootUnwindRva, alignedGcInfoRva } = source.layout;
  source.bytes.set([1, 0, 1, 0], rootUnwindRva);

  assert.equal(await locateReadyToRunGcInfo(source.reader(), source.mapper, rootUnwindRva),
    alignedGcInfoRva + 4);
  assert.equal(await locateNativeAotGcInfo(source.reader(), source.mapper, rootUnwindRva),
    rootUnwindRva + 7);
  source.bytes[rootUnwindRva] = 9; // UNW_FLAG_EHANDLER aligns the personality DWORD.
  source.bytes[alignedGcInfoRva + 4] = 0x14; // Associated-data plus EH relative pointers.
  assert.equal(await locateNativeAotGcInfo(source.reader(), source.mapper, rootUnwindRva),
    alignedGcInfoRva + 13);
});

void test("rejects missing optional pointers rather than jumping across unmapped bytes", async () => {
  const source = managedGcContainerFixture();
  const truncatedUnwindRva = source.bytes.length - 8;
  source.bytes.set([1, 0, 0, 0, 0x14], truncatedUnwindRva);

  await assert.rejects(locateNativeAotGcInfo(source.reader(), source.mapper, truncatedUnwindRva),
    /truncated/);
  source.bytes.set([1, 0, 255, 0], truncatedUnwindRva);
  await assert.rejects(locateReadyToRunGcInfo(source.reader(), source.mapper, truncatedUnwindRva),
    /truncated/);
});

void test("rejects malformed unwind headers and leaves funclets bound to their root map", async () => {
  const source = managedGcContainerFixture();
  const { rootUnwindRva } = source.layout;
  source.bytes.set([1, 0, 0, 0, 1], rootUnwindRva);

  assert.equal(await locateNativeAotGcInfo(source.reader(), source.mapper, rootUnwindRva), null);
  source.bytes[rootUnwindRva + 4] = 0xe0;
  await assert.rejects(locateNativeAotGcInfo(source.reader(), source.mapper, rootUnwindRva),
    /reserved/);
  source.bytes[rootUnwindRva] = 3;
  await assert.rejects(locateReadyToRunGcInfo(source.reader(), source.mapper, rootUnwindRva),
    /version/);
  source.bytes[rootUnwindRva] = 33;
  await assert.rejects(locateReadyToRunGcInfo(source.reader(), source.mapper, rootUnwindRva),
    /chained/);
  await assert.rejects(locateReadyToRunGcInfo(source.reader(), source.mapper,
    source.bytes.length - 1), /truncated/);
  const finalUnwindRva = source.bytes.length - 4;
  source.bytes.set([1, 0, 0, 0], finalUnwindRva);
  await assert.rejects(locateNativeAotGcInfo(source.reader(), source.mapper, finalUnwindRva),
    /truncated/);
});

void test("rejects holes in unwind codes even when the following GC tail is mapped", async () => {
  const source = managedGcContainerFixture();
  const { rootUnwindRva } = source.layout;
  source.bytes.set([1, 0, 4, 0], rootUnwindRva);

  await assert.rejects(locateNativeAotGcInfo(source.reader(),
    rva => rva === rootUnwindRva + 4 ? null : rva, rootUnwindRva),
  /codes or personality are truncated/);
});
