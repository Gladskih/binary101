import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfNativeAotGc } from "../../../../analyzers/elf/native-aot-gc.js";
import { parseElfLsda } from "../../../../analyzers/elf/lsda.js";
import { elfManagedGcAddress, elfManagedGcFixture, elfManagedGcFrame } from
  "../../../helpers/elf-managed-gc-fixture.js";

void test("decodes NativeAOT ELF GC maps and separates their LSDA format from Itanium", async () => {
  const source = elfManagedGcFixture();

  const nativeLsdas = await readElfNativeAotGc(source.file(), source.elf);

  assert.equal(source.elf.nativeAot?.methodGcMaps?.methods[0]?.info.header.codeLength, 32);
  assert.deepEqual([...nativeLsdas], [elfManagedGcAddress(64)]);
  assert.deepEqual(await parseElfLsda(source.file(), source.elf, nativeLsdas), []);
  assert.deepEqual(source.elf.nativeAot?.methodGcMaps?.warnings, []);
});

void test("recognizes funclet links but does not guess unnamed roots from a shared CIE", async () => {
  const source = elfManagedGcFixture();
  const { bytes, view, managed } = source;
  const secondLsdaRva = 96;
  const handlerRva = 128;
  bytes.set(managed.gc, secondLsdaRva + 1);
  bytes[handlerRva] = 1; // NativeAOT handler funclet, not a second GC payload.
  view.setInt32(handlerRva + 1, -65, true); // Relative pointer to the known root LSDA.
  view.setInt32(handlerRva + 5, 64, true); // Funclet's distance from its root method.
  source.elf.unwind = [{ sectionIndex: 1, issues: [], cies: [{ offset: 0, version: 1,
    augmentation: "zLR", addressSize: 8, codeAlignment: 1n, dataAlignment: -8n,
    returnRegister: 16n, fdeEncoding: 27, lsdaEncoding: 27, personality: null, instructions: [] }],
  fdes: [{ ...elfManagedGcFrame(32, 64), offset: 0 },
  { ...elfManagedGcFrame(64, 96), offset: 16 },
  { ...elfManagedGcFrame(96, 128), offset: 32 }] }];

  const nativeLsdas = await readElfNativeAotGc(source.file(), source.elf);

  assert.deepEqual([...nativeLsdas], [elfManagedGcAddress(64), elfManagedGcAddress(128)]);
  assert.equal(source.elf.nativeAot?.methodGcMaps?.methods.length, 1);
});

void test("ignores unconfirmed formats and warns on missing file-backed GC storage", async () => {
  const source = elfManagedGcFixture();
  delete source.elf.nativeAot;
  assert.equal((await readElfNativeAotGc(source.file(), source.elf)).size, 0);
  source.elf.nativeAot = source.managed.metadata;
  source.elf.unwind = [{ sectionIndex: 1, cies: [], issues: [], fdes: [{ offset: 0, cieOffset: 0,
    start: { address: elfManagedGcAddress(32), indirect: false }, range: 32n,
    lsda: { address: elfManagedGcAddress(64), indirect: false }, instructions: [] }] }];
  source.elf.programHeaders[0]!.filesz = BigInt(source.managed.layout.rootUnwindRva);

  await readElfNativeAotGc(source.file(), source.elf);

  assert.match(source.elf.nativeAot?.methodGcMaps?.warnings.join() ?? "", /file-backed/);
});

void test("does not decode unsupported architectures or indirect/missing LSDA pointers", async () => {
  const source = elfManagedGcFixture();
  // EM_386=3 and EM_X86_64=62 are the gABI machine IDs; the decoder also requires
  // ELF64 little-endian input.
  // https://gabi.xinuos.com/elf/02-eheader.html
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
  source.bytes[source.managed.layout.rootUnwindRva + 1] = 0;
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
