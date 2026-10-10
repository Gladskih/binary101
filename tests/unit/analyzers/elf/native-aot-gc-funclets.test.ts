import assert from "node:assert/strict";
import { test } from "node:test";
import { identifyNativeAotGcFunclets } from "../../../../analyzers/elf/native-aot-gc-funclets.js";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { elfManagedGcFixture, elfManagedGcFrame } from "../../../helpers/elf-managed-gc-fixture.js";

void test("requires both a known root LSDA and a matching root code start", async () => {
  const source = elfManagedGcFixture();
  const root = source.elf.unwind![0]!.fdes[0]!;
  source.elf.unwind![0]!.fdes.push(elfManagedGcFrame(64, 96), elfManagedGcFrame(96, 128));
  source.bytes[96] = 2;
  source.view.setInt32(97, -33, true);
  source.view.setInt32(101, 32, true);
  source.bytes[128] = 1;
  source.view.setInt32(129, -65, true);
  source.view.setInt32(133, 1, true); // Wrong distance must not classify unrelated LSDA bytes.
  const native = new Set([4160n]);

  await identifyNativeAotGcFunclets(createFileRangeReader(source.file(), 0, source.bytes.length),
    source.elf, [root], native);

  assert.deepEqual([...native], [4160n, 4192n]);
});

void test("ignores missing pointers, reserved flags and truncated funclet links", async () => {
  const source = elfManagedGcFixture();
  const root = source.elf.unwind![0]!.fdes[0]!;
  source.elf.unwind![0]!.fdes.push({ ...elfManagedGcFrame(), lsda: null },
    { ...elfManagedGcFrame(), start: null },
    { ...elfManagedGcFrame(), start: { address: 4128n, indirect: true } },
    { ...elfManagedGcFrame(), lsda: { address: 4160n, indirect: true } },
    elfManagedGcFrame(64, 1024), elfManagedGcFrame(64, 96));
  source.bytes[96] = 0xe1;
  const native = new Set<bigint>();

  await identifyNativeAotGcFunclets(createFileRangeReader(source.file(), 0, source.bytes.length),
    source.elf, [root, { ...root, lsda: null }], native);

  assert.equal(native.size, 0);
  const reader = createFileRangeReader(source.file(), 0, source.bytes.length);
  reader.read = async () => new DataView(new ArrayBuffer(0));
  await identifyNativeAotGcFunclets(reader, source.elf, [root], native);
  assert.equal(native.size, 0);
});
