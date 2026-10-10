import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfNativeAotGc } from "../../../../analyzers/elf/native-aot-gc.js";
import { parseElfLsda } from "../../../../analyzers/elf/lsda.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";
import { managedGcContainerFixture } from "../../../helpers/managed-gc-container-fixture.js";
import { elfManagedGcFixture, elfManagedGcFrame } from "../../../helpers/elf-managed-gc-fixture.js";

void test("decodes NativeAOT ELF GC maps and separates their LSDA format from Itanium", async () => {
  const source = relocationFixture();
  const managed = managedGcContainerFixture();
  source.elf.nativeAot = managed.metadata;
  source.elf.programHeaders.push({ index: 0, type: 1, typeName: null, offset: 0n, vaddr: 4096n,
    paddr: 4096n, filesz: 1024n, memsz: 1024n, flags: 5, flagNames: [], align: 1n });
  source.bytes.set(managed.gc, 65);
  source.elf.unwind = [{ sectionIndex: 1, cies: [], issues: [], fdes: [{
    offset: 0, cieOffset: 0, start: { address: 4128n, indirect: false }, range: 32n,
    lsda: { address: 4160n, indirect: false }, instructions: [] }] }];

  const nativeLsdas = await readElfNativeAotGc(source.file(), source.elf);

  assert.equal(source.elf.nativeAot.methodGcMaps?.methods[0]?.info.header.codeLength, 32);
  assert.deepEqual([...nativeLsdas], [4160n]);
  assert.deepEqual(await parseElfLsda(source.file(), source.elf, nativeLsdas), []);
  assert.deepEqual(source.elf.nativeAot.methodGcMaps?.warnings, []);
});

void test("recognizes funclet links but does not guess unnamed roots from a shared CIE", async () => {
  const source = relocationFixture();
  const managed = managedGcContainerFixture();
  source.elf.nativeAot = managed.metadata;
  source.elf.programHeaders.push({ index: 0, type: 1, typeName: null, offset: 0n, vaddr: 4096n,
    paddr: 4096n, filesz: 1024n, memsz: 1024n, flags: 5, flagNames: [], align: 1n });
  source.bytes.set(managed.gc, 65);
  source.bytes.set(managed.gc, 97);
  source.bytes[128] = 1; // NativeAOT handler funclet, not a second GC payload.
  source.view.setInt32(129, -65, true); // Relative pointer to the known root LSDA.
  source.view.setInt32(133, 64, true); // Funclet's distance from its root method.
  source.elf.unwind = [{ sectionIndex: 1, issues: [], cies: [{ offset: 0, version: 1,
    augmentation: "zLR", addressSize: 8, codeAlignment: 1n, dataAlignment: -8n,
    returnRegister: 16n, fdeEncoding: 27, lsdaEncoding: 27, personality: null, instructions: [] }],
  fdes: [{ offset: 0, cieOffset: 0, start: { address: 4128n, indirect: false }, range: 32n,
    lsda: { address: 4160n, indirect: false }, instructions: [] },
  { offset: 16, cieOffset: 0, start: { address: 4160n, indirect: false }, range: 32n,
    lsda: { address: 4192n, indirect: false }, instructions: [] },
  { offset: 32, cieOffset: 0, start: { address: 4192n, indirect: false }, range: 32n,
    lsda: { address: 4224n, indirect: false }, instructions: [] }] }];

  const nativeLsdas = await readElfNativeAotGc(source.file(), source.elf);

  assert.deepEqual([...nativeLsdas], [4160n, 4224n]);
  assert.equal(source.elf.nativeAot.methodGcMaps?.methods.length, 1);
});

void test("ignores unconfirmed formats and warns on missing file-backed GC storage", async () => {
  const source = relocationFixture();
  const managed = managedGcContainerFixture();
  assert.equal((await readElfNativeAotGc(source.file(), source.elf)).size, 0);
  source.elf.nativeAot = managed.metadata;
  source.elf.unwind = [{ sectionIndex: 1, cies: [], issues: [], fdes: [{ offset: 0, cieOffset: 0,
    start: { address: 32n, indirect: false }, range: 32n,
    lsda: { address: 64n, indirect: false }, instructions: [] }] }];
  source.elf.programHeaders.push({ index: 0, type: 1, typeName: null, offset: 0n, vaddr: 0n,
    paddr: 0n, filesz: 32n, memsz: 1024n, flags: 5, flagNames: [], align: 1n });

  await readElfNativeAotGc(source.file(), source.elf);

  assert.match(source.elf.nativeAot.methodGcMaps?.warnings.join() ?? "", /file-backed/);
});

void test("does not decode unsupported architectures or indirect/missing LSDA pointers", async () => {
  const source = elfManagedGcFixture();
  source.elf.header.machine = 3;
  assert.equal((await readElfNativeAotGc(source.file(), source.elf)).size, 0);
  source.elf.header.machine = 62;
  source.elf.littleEndian = false;
  assert.equal((await readElfNativeAotGc(source.file(), source.elf)).size, 0);
  source.elf.littleEndian = true;
  source.elf.unwind![0]!.fdes[0]!.lsda!.indirect = true;
  assert.equal((await readElfNativeAotGc(source.file(), source.elf)).size, 0);
  source.elf.unwind![0]!.fdes[0]!.lsda = null;
  assert.equal((await readElfNativeAotGc(source.file(), source.elf)).size, 0);
  delete source.elf.unwind;
  delete source.managed.metadata.stackTraceMap;
  assert.equal((await readElfNativeAotGc(source.file(), source.elf)).size, 0);
  source.managed.metadata.majorVersion = 10;
  assert.equal((await readElfNativeAotGc(source.file(), source.elf)).size, 0);
  source.elf.programHeaders = [];
  assert.equal((await readElfNativeAotGc(source.file(), source.elf)).size, 0);
});

void test("retains null identities and GC/funclet read warnings without rejecting the image", async () => {
  const source = elfManagedGcFixture();
  source.managed.metadata.stackTraceMap!.entries.push({ command: 0, methodRva: null });
  source.bytes[65] = 0;
  await readElfNativeAotGc(source.file(), source.elf);
  assert.match(source.managed.metadata.methodGcMaps?.warnings.join() ?? "", /zero code length/);
  source.elf.unwind![0]!.fdes.push(elfManagedGcFrame(64, 96));
  const file = source.file();
  test.mock.method(file, "slice", () => { throw new Error("read failed"); });

  await readElfNativeAotGc(file, source.elf);

  assert.match(source.managed.metadata.methodGcMaps?.warnings.join() ?? "", /GC funclets: read failed/);
  test.mock.method(file, "slice", () => { throw "untyped read failed"; });
  await readElfNativeAotGc(file, source.elf);
  assert.match(source.managed.metadata.methodGcMaps?.warnings.join() ?? "", /GC info: untyped read failed/);
  assert.match(source.managed.metadata.methodGcMaps?.warnings.join() ?? "", /GC funclets: untyped read failed/);
});
