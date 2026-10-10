import assert from "node:assert/strict";
import { test } from "node:test";
import { ElfNativeAotGcBlobs } from "../../../../analyzers/elf/native-aot-gc-blobs.js";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { elfManagedGcFixture } from "../../../helpers/elf-managed-gc-fixture.js";

void test("caches shared GC blobs and respects the next LSDA boundary", async () => {
  const source = elfManagedGcFixture();
  const blobs = new ElfNativeAotGcBlobs(createFileRangeReader(source.file(), 0, source.bytes.length),
    source.elf.programHeaders, new Set([4192n, 4160n, 4200n]), 4, new Set());

  const first = blobs.read(4160n);

  assert.equal(blobs.read(4160n), first);
  assert.equal((await first)?.header.codeLength, 32);
  const beyondSegment = new ElfNativeAotGcBlobs(
    createFileRangeReader(source.file(), 0, source.bytes.length), source.elf.programHeaders,
    new Set([4160n, 8192n]), 4, new Set());
  assert.equal((await beyondSegment.read(4160n))?.header.codeLength, 32);
});

void test("keeps GC header/body warnings and distinguishes root, handler and reserved flags", async () => {
  const source = elfManagedGcFixture();
  source.bytes.set([1, 0xe0, 3, 0x14], 96);
  const warnings = new Set<string>();
  const blobs = new ElfNativeAotGcBlobs(createFileRangeReader(source.file(), 0, source.bytes.length),
    source.elf.programHeaders, new Set([4192n, 4193n, 4194n, 4195n, 4196n]), 4, warnings);

  assert.equal(await blobs.read(4192n), null);
  await assert.rejects(blobs.read(4193n), /reserved/);
  await assert.rejects(blobs.read(4194n), /reserved/);
  await assert.rejects(blobs.read(4195n), /truncated/);
  assert.equal(await blobs.read(4196n), null);
  assert.match([...warnings].join(), /zero code length/);
});

void test("rejects missing or short file-backed LSDA records", async () => {
  const source = elfManagedGcFixture();
  source.elf.programHeaders[0]!.filesz = 2048n;
  source.elf.programHeaders[0]!.memsz = 2048n;
  const blobs = new ElfNativeAotGcBlobs(createFileRangeReader(source.file(), 0, source.bytes.length),
    source.elf.programHeaders, new Set(), 4, new Set());

  await assert.rejects(blobs.read(4095n), /file-backed/);
  await assert.rejects(blobs.read(4160n), /truncated/);
  const reader = createFileRangeReader(source.file(), 0, source.bytes.length);
  reader.read = async () => new DataView(new ArrayBuffer(0));
  source.elf.programHeaders[0]!.filesz = 1024n;
  const empty = new ElfNativeAotGcBlobs(reader, source.elf.programHeaders, new Set(), 4, new Set());
  await assert.rejects(empty.read(4160n), /flags are truncated/);
});
