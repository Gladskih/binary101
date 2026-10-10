import assert from "node:assert/strict";
import { test } from "node:test";
import { identifyNativeAotGcFunclets } from "../../../../analyzers/elf/native-aot-gc-funclets.js";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { elfManagedGcAddress, elfManagedGcFixture, elfManagedGcFrame } from
  "../../../helpers/elf-managed-gc-fixture.js";

void test("requires both a known root LSDA and a matching root code start", async () => {
  const source = elfManagedGcFixture();
  const root = source.elf.unwind![0]!.fdes[0]!;
  const { nextUnwindRva } = source.managed.layout;
  const secondFuncletRva = nextUnwindRva + 32;
  source.elf.unwind![0]!.fdes.push(elfManagedGcFrame(64, nextUnwindRva),
    elfManagedGcFrame(96, secondFuncletRva));
  source.bytes[nextUnwindRva] = 2;
  source.view.setInt32(nextUnwindRva + 1, -33, true);
  source.view.setInt32(nextUnwindRva + 5, 32, true);
  source.bytes[secondFuncletRva] = 1;
  source.view.setInt32(secondFuncletRva + 1, -65, true);
  source.view.setInt32(secondFuncletRva + 5, 1, true); // Wrong root distance rejects this link.
  const native = new Set([elfManagedGcAddress(source.managed.layout.rootUnwindRva)]);

  await identifyNativeAotGcFunclets(createFileRangeReader(source.file(), 0, source.bytes.length),
    source.elf, [root], native);

  assert.deepEqual([...native], [elfManagedGcAddress(source.managed.layout.rootUnwindRva),
    elfManagedGcAddress(nextUnwindRva)]);
});

void test("ignores missing pointers, reserved flags and truncated funclet links", async () => {
  const source = elfManagedGcFixture();
  const root = source.elf.unwind![0]!.fdes[0]!;
  source.elf.unwind![0]!.fdes.push({ ...elfManagedGcFrame(), lsda: null },
    { ...elfManagedGcFrame(), start: null },
    { ...elfManagedGcFrame(), start: { address: 4128n, indirect: true } },
    { ...elfManagedGcFrame(), lsda: { address: 4160n, indirect: true } },
    elfManagedGcFrame(64, source.bytes.length),
    elfManagedGcFrame(64, source.managed.layout.nextUnwindRva));
  source.bytes[source.managed.layout.nextUnwindRva] = 0xe1;
  const native = new Set<bigint>();

  await identifyNativeAotGcFunclets(createFileRangeReader(source.file(), 0, source.bytes.length),
    source.elf, [root, { ...root, lsda: null }], native);

  assert.equal(native.size, 0);
  const reader = createFileRangeReader(source.file(), 0, source.bytes.length);
  reader.read = async () => new DataView(new ArrayBuffer(0));
  await identifyNativeAotGcFunclets(reader, source.elf, [root], native);
  assert.equal(native.size, 0);
});
