import assert from "node:assert/strict";
import { test } from "node:test";
import { PeManagedGcBlobs } from "../../../../../../analyzers/pe/exception/amd64/managed-gc-blobs.js";
import { managedGcContainerFixture } from "../../../../../helpers/managed-gc-container-fixture.js";

void test("caches shared payloads and bounds reads at the following unwind record", async () => {
  const source = managedGcContainerFixture();
  const { rootUnwindRva, rootGcInfoRva, nextUnwindRva } = source.layout;
  source.bytes.set(source.gc, rootGcInfoRva);
  const blobs = new PeManagedGcBlobs(source.reader(), source.mapper,
    new Set([rootUnwindRva, nextUnwindRva]), 4, new Set());

  const first = blobs.read(rootUnwindRva, rootGcInfoRva);

  assert.equal(blobs.read(rootUnwindRva, rootGcInfoRva), first);
  assert.equal((await first)?.header.codeLength, 32);
});

void test("reports unmapped, overlapping and truncated payloads", async () => {
  const source = managedGcContainerFixture();
  const { rootUnwindRva, rootGcInfoRva } = source.layout;
  const warnings = new Set<string>();
  const blobs = new PeManagedGcBlobs(source.reader(), source.mapper,
    new Set([rootUnwindRva, rootUnwindRva + 4]), 4, warnings);

  assert.equal(await blobs.read(rootUnwindRva, rootGcInfoRva), null);
  assert.equal(await blobs.read(rootUnwindRva + 4, source.bytes.length), null);
  assert.equal(await blobs.read(rootUnwindRva + 4, source.bytes.length - 1), null);
  assert.match([...warnings].join(), /overlaps/);
  assert.match([...warnings].join(), /truncated/);
});
