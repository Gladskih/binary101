import assert from "node:assert/strict";
import { test } from "node:test";
import { PeManagedGcBlobs } from "../../../../../../analyzers/pe/exception/amd64/managed-gc-blobs.js";
import { managedGcContainerFixture } from "../../../../../helpers/managed-gc-container-fixture.js";

void test("caches shared payloads and bounds reads at the following unwind record", async () => {
  const source = managedGcContainerFixture();
  source.bytes.set(source.gc, 69);
  const blobs = new PeManagedGcBlobs(source.reader(), source.mapper, new Set([64, 96]), 4, new Set());

  const first = blobs.read(64, 69);

  assert.equal(blobs.read(64, 69), first);
  assert.equal((await first)?.header.codeLength, 32);
});

void test("reports unmapped, overlapping and truncated payloads", async () => {
  const source = managedGcContainerFixture();
  const warnings = new Set<string>();
  const blobs = new PeManagedGcBlobs(source.reader(), source.mapper, new Set([64, 68]), 4, warnings);

  assert.equal(await blobs.read(64, 69), null);
  assert.equal(await blobs.read(68, 256), null);
  assert.equal(await blobs.read(68, 255), null);
  assert.match([...warnings].join(), /overlaps/);
  assert.match([...warnings].join(), /truncated/);
});
