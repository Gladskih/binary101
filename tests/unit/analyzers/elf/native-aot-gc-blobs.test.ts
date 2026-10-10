import assert from "node:assert/strict";
import { test } from "node:test";
import { ElfNativeAotGcBlobs } from "../../../../analyzers/elf/native-aot-gc-blobs.js";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { elfManagedGcAddress, elfManagedGcFixture } from
  "../../../helpers/elf-managed-gc-fixture.js";

void test("caches shared GC blobs and respects the next LSDA boundary", async () => {
  const source = elfManagedGcFixture();
  const blobs = new ElfNativeAotGcBlobs(createFileRangeReader(source.file(), 0, source.bytes.length),
    source.elf.programHeaders, new Set([elfManagedGcAddress(96), elfManagedGcAddress(64),
      elfManagedGcAddress(104)]), 4, new Set());

  const first = blobs.read(elfManagedGcAddress(64));

  assert.equal(blobs.read(elfManagedGcAddress(64)), first);
  assert.equal((await first)?.header.codeLength, 32);
  const beyondSegment = new ElfNativeAotGcBlobs(
    createFileRangeReader(source.file(), 0, source.bytes.length), source.elf.programHeaders,
    new Set([elfManagedGcAddress(64), elfManagedGcAddress(source.bytes.length)]), 4, new Set());
  assert.equal((await beyondSegment.read(elfManagedGcAddress(64)))?.header.codeLength, 32);
});

void test("keeps GC header/body warnings and distinguishes root, handler and reserved flags", async () => {
  const source = elfManagedGcFixture();
  source.bytes.set([1, 0xe0, 3, 0x14], source.managed.layout.rootUnwindRva + 32);
  const warnings = new Set<string>();
  const blobs = new ElfNativeAotGcBlobs(createFileRangeReader(source.file(), 0, source.bytes.length),
    source.elf.programHeaders, new Set([96, 97, 98, 99, 100].map(elfManagedGcAddress)),
    4, warnings);

  assert.equal(await blobs.read(elfManagedGcAddress(96)), null);
  await assert.rejects(blobs.read(elfManagedGcAddress(97)), /reserved/);
  await assert.rejects(blobs.read(elfManagedGcAddress(98)), /reserved/);
  await assert.rejects(blobs.read(elfManagedGcAddress(99)), /truncated/);
  assert.equal(await blobs.read(elfManagedGcAddress(100)), null);
  assert.match([...warnings].join(), /zero code length/);
});

void test("rejects missing or short file-backed LSDA records", async () => {
  const source = elfManagedGcFixture();
  source.elf.programHeaders[0]!.filesz = BigInt(source.bytes.length) * 2n;
  source.elf.programHeaders[0]!.memsz = BigInt(source.bytes.length) * 2n;
  const blobs = new ElfNativeAotGcBlobs(createFileRangeReader(source.file(), 0, source.bytes.length),
    source.elf.programHeaders, new Set(), 4, new Set());

  await assert.rejects(blobs.read(elfManagedGcAddress(-1)), /file-backed/);
  await assert.rejects(blobs.read(elfManagedGcAddress(64)), /truncated/);
  const reader = createFileRangeReader(source.file(), 0, source.bytes.length);
  reader.read = async () => new DataView(new ArrayBuffer(0));
  source.elf.programHeaders[0]!.filesz = BigInt(source.bytes.length);
  const empty = new ElfNativeAotGcBlobs(reader, source.elf.programHeaders, new Set(), 4, new Set());
  await assert.rejects(empty.read(elfManagedGcAddress(64)), /flags are truncated/);
});
