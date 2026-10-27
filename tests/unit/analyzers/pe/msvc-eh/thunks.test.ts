import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeEhThunk } from "../../../../../analyzers/pe/msvc-eh/thunks.js";
import { createEhImage } from "../../../../../analyzers/pe/msvc-eh/image.js";
import { createEhFixture } from "../../../../fixtures/pe-msvc-eh.js";

void test("AMD64 thunk resolves the IAT slot and never its current pointer value", async () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  assert.deepEqual(await decodeEhThunk(createEhImage(fixture.file, fixture.core), subject.handlerRva),
    { kind: "import", rva: subject.iatRva });
});

for (const [offset, value] of [[0, 0x90000011], [4, 0xf9400230], [8, 0xd61f0220]]) {
  void test(`ARM64 import thunks reject an independently invalid word at ${offset}`, async () => {
    const subject = createEhFixture();
    subject.builder.patchUint32(subject.handlerRva, 0, 0x90000010); // ADRP x16, current page.
    subject.builder.patchUint32(subject.handlerRva, 4, 0xf9400610); // LDR x16,[x16,#8].
    subject.builder.patchUint32(subject.handlerRva, 8, 0xd61f0200); // BR x16.
    subject.builder.patchUint32(subject.handlerRva, offset!, value!);
    const fixture = subject.builder.build();
    fixture.core.coff.Machine = 0xaa64;
    assert.equal(await decodeEhThunk(createEhImage(fixture.file, fixture.core), subject.handlerRva), null);
  });
}

void test("ARM64 import thunks include the scaled LDR displacement", async () => {
  const subject = createEhFixture();
  subject.builder.patchUint32(subject.handlerRva, 0, 0x90000010);
  subject.builder.patchUint32(subject.handlerRva, 4, 0xf9400610); // LDR x16,[x16,#8].
  subject.builder.patchUint32(subject.handlerRva, 8, 0xd61f0200);
  const fixture = subject.builder.build();
  fixture.core.coff.Machine = 0xaa64;
  assert.deepEqual(await decodeEhThunk(createEhImage(fixture.file, fixture.core), subject.handlerRva),
    { kind: "import", rva: 0x1008 });
});

void test("valid thunk bytes in non-executable data are not handler identity", async () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  fixture.core.sections[0]!.characteristics &= ~0x20000000; // Clear IMAGE_SCN_MEM_EXECUTE, retain MEM_READ.
  assert.equal(await decodeEhThunk(createEhImage(fixture.file, fixture.core), subject.handlerRva), null);
});

void test("ARMNT import thunk reconstructs MOVW/MOVT's preferred VA", async () => {
  const subject = createEhFixture();
  subject.builder.patchUint32(subject.handlerRva, 0, 0x0c00f242); // movw ip, #0x2000.
  subject.builder.patchUint32(subject.handlerRva, 4, 0x0c00f2c1); // movt ip, #0x1000.
  subject.builder.patchUint32(subject.handlerRva, 8, 0xf000f8dc); // ldr.w pc, [ip].
  const fixture = subject.builder.build();
  fixture.core.coff.Machine = 0x1c4;
  fixture.core.opt.ImageBase = 0x10000000n;
  assert.deepEqual(await decodeEhThunk(createEhImage(fixture.file, fixture.core), subject.handlerRva),
    { kind: "import", rva: 0x2000 });
});

void test("x86 import thunks use absolute IAT addresses", async () => {
  const subject = createEhFixture();
  subject.builder.patchUint32(subject.handlerRva, 2, 0x400000 + subject.iatRva);
  const fixture = subject.builder.build();
  fixture.core.coff.Machine = 0x14c;
  fixture.core.opt.ImageBase = 0x400000n;
  assert.deepEqual(await decodeEhThunk(createEhImage(fixture.file, fixture.core), subject.handlerRva),
    { kind: "import", rva: subject.iatRva });
});

for (const [instruction, displacement] of [[0x14000004, 16], [0x17ffffff, -4]]) {
  void test(`ARM64 direct branch decodes displacement ${displacement}`, async () => {
    const subject = createEhFixture();
    subject.builder.patchUint32(subject.handlerRva, 0, instruction!);
    const fixture = subject.builder.build();
    fixture.core.coff.Machine = 0xaa64;
    assert.deepEqual(await decodeEhThunk(createEhImage(fixture.file, fixture.core), subject.handlerRva),
      { kind: "branch", rva: subject.handlerRva + displacement! });
  });
}

void test("ARM64 ADRP sign extension preserves a negative page displacement", async () => {
  const subject = createEhFixture();
  subject.builder.patchUint32(subject.handlerRva, 0, 0xf0fffff0);
  subject.builder.patchUint32(subject.handlerRva, 4, 0xf9400210);
  subject.builder.patchUint32(subject.handlerRva, 8, 0xd61f0200);
  const fixture = subject.builder.build();
  fixture.core.coff.Machine = 0xaa64;
  assert.deepEqual(await decodeEhThunk(createEhImage(fixture.file, fixture.core), subject.handlerRva),
    { kind: "import", rva: 0 });
});

for (const [offset, value] of [[0, 0x0c00f000], [4, 0x0c00f200], [2, 0x8000],
  [6, 0x8000], [8, 0xffff]]) {
  void test(`Thumb thunk rejects changed instruction at ${offset}`, async () => {
    const subject = createEhFixture();
    subject.builder.patchUint32(subject.handlerRva, 0, 0x0c00f242);
    subject.builder.patchUint32(subject.handlerRva, 4, 0x0c00f2c1);
    subject.builder.patchUint32(subject.handlerRva, 8, 0xf000f8dc);
    subject.builder.view.setUint32(subject.builder.offsetOf(subject.handlerRva + offset!), value!, true);
    const fixture = subject.builder.build();
    fixture.core.coff.Machine = 0x1c4;
    assert.equal(await decodeEhThunk(createEhImage(fixture.file, fixture.core), subject.handlerRva), null);
  });
}

void test("thunk decoding rejects short reads and unsupported instruction sets", async () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  image.read = async () => null;
  assert.equal(await decodeEhThunk(image, subject.handlerRva), null);
  assert.equal(await decodeEhThunk(image, subject.iatRva), null);
  fixture.core.coff.Machine = 0x5032;
  image.read = (rva, size) => fixture.file.read(fixture.core.rvaToOff(rva)!, size);
  assert.equal(await decodeEhThunk(image, subject.handlerRva), null);
});

void test("ARM64 rejects unaligned addresses and a thunk with a different branch register", async () => {
  const subject = createEhFixture();
  subject.builder.patchUint32(subject.handlerRva, 0, 0xb0000010);
  subject.builder.patchUint32(subject.handlerRva, 4, 0xf9400210);
  subject.builder.patchUint32(subject.handlerRva, 8, 0xd61f0220);
  const fixture = subject.builder.build();
  fixture.core.coff.Machine = 0xaa64;
  const image = createEhImage(fixture.file, fixture.core);
  assert.equal(await decodeEhThunk(image, subject.handlerRva), null);
  assert.equal(await decodeEhThunk(image, subject.handlerRva + 1), null);
});

void test("ARM64 import thunk uses ADRP/LDR/BR with matching registers", async () => {
  const subject = createEhFixture();
  subject.builder.setMachine(0xaa64);
  // LLD COFF/Chunks.h importThunkARM64; ADRP at page 0x1000 targets 0x2000.
  subject.builder.patchUint32(subject.handlerRva, 0, 0xb0000010);
  subject.builder.patchUint32(subject.handlerRva, 4, 0xf9400210);
  subject.builder.patchUint32(subject.handlerRva, 8, 0xd61f0200);
  const fixture = subject.builder.build();
  assert.deepEqual(await decodeEhThunk(createEhImage(fixture.file, fixture.core), subject.handlerRva),
    { kind: "import", rva: 0x2000 });
});
