import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeX86Eh } from "../../../../../analyzers/pe/msvc-eh/x86.js";
import { createEhImage } from "../../../../../analyzers/pe/msvc-eh/image.js";
import { createEhPersonalityResolver } from "../../../../../analyzers/pe/msvc-eh/personality.js";
import { createPeLoadConfigResult } from "../../../../../analyzers/pe/load-config/result.js";
import { createEhFixture, addFh3 } from "../../../../fixtures/pe-msvc-eh.js";
import { analyzeMsvcEh } from "../../../../../analyzers/pe/msvc-eh/index.js";

const absoluteFh3Fixture = () => {
  const subject = createEhFixture();
  subject.imports.thunkEntrySize = 4; // PE32 IMAGE_THUNK_DATA32, unlike the shared PE32+ fixture.
  const { infoRva, unwindRva, tryMapRva, handlerMapRva } = addFh3(subject);
  const base = 0x400000;
  subject.builder.patchUint32(infoRva, 8, base + unwindRva);
  subject.builder.patchUint32(infoRva, 16, base + tryMapRva);
  subject.builder.patchUint32(infoRva, 20, 0);
  subject.builder.patchUint32(infoRva, 24, 0);
  subject.builder.patchUint32(tryMapRva, 16, base + handlerMapRva);
  subject.builder.patchUint32(handlerMapRva, 12, base + subject.catchRva);
  const stub = subject.builder.allocateFunctionTarget();
  subject.builder.patchByte(stub, 0xb8);
  subject.builder.patchUint32(stub, 1, base + infoRva);
  subject.builder.patchByte(stub + 5, 0xe9);
  subject.builder.patchInt32(stub, 6, subject.handlerRva - stub - 10);
  subject.builder.patchUint32(subject.handlerRva, 2, base + subject.iatRva);
  return { ...subject, stub, infoRva, base };
};

const x86Subject = (subject: ReturnType<typeof absoluteFh3Fixture>) => {
  const fixture = subject.builder.build();
  fixture.core.coff.Machine = 0x14c;
  fixture.core.opt = { ...fixture.core.opt, Magic: 0x10b, BaseOfData: 0x2000, ImageBase: BigInt(subject.base) };
  const image = createEhImage(fixture.file, fixture.core);
  const lc = createPeLoadConfigResult();
  lc.tables = { safeSehHandler: { name: "SafeSEH", kind: "safeSeh", tableVa: 0n,
    tableRva: 0x2000, declaredCount: 1, entrySize: 4, truncated: false,
    entries: [{ index: 0, rva: subject.stub }] } };
  return { image, lc, resolve: createEhPersonalityResolver(image, subject.imports, []) };
};

void test("x86 FH3 is anchored by SafeSEH and exact mov-eax/jmp stub", async () => {
  const subject = absoluteFh3Fixture();
  const { stub, infoRva, base } = subject;
  subject.builder.truncateAtRva(infoRva + 36); // The x86 FuncInfo ends after exactly nine DWORDs.
  const fixture = subject.builder.build();
  const core = { ...fixture.core, coff: { ...fixture.core.coff, Machine: 0x14c },
    opt: { ...fixture.core.opt, Magic: 0x10b as const, BaseOfData: 0x2000, ImageBase: BigInt(base) } };
  const image = createEhImage(fixture.file, core);
  const lc = createPeLoadConfigResult();
  lc.tables = { safeSehHandler: { name: "SafeSEH", kind: "safeSeh", tableVa: 0n,
    tableRva: 0x2000, declaredCount: 1, entrySize: 4, truncated: false,
    entries: [{ index: 0, rva: stub }] } };
  const analysis = await analyzeX86Eh(image, createEhPersonalityResolver(image, subject.imports, []), lc);
  assert.equal(analysis.records[0]?.functionInfo?.rva, infoRva);
  assert.deepEqual(analysis.warnings, []);
  assert.equal((await analyzeMsvcEh(fixture.file, core, null, subject.imports, [], lc))?.records[0]?.functionInfo?.rva,
    infoRva);
});

for (const name of ["_except_handler3", "_except_handler4"] as const) {
  void test(`x86 reports a named SafeSEH ${name} registration without claiming decoded scopes`, async () => {
    const subject = createEhFixture();
    const fixture = subject.builder.build();
    fixture.core.coff.Machine = 0x14c;
    const image = createEhImage(fixture.file, fixture.core);
    const lc = createPeLoadConfigResult();
    lc.tables = { safeSehHandler: { name: "SafeSEH", kind: "safeSeh", tableVa: 0n,
      tableRva: 0x2000, declaredCount: 1, entrySize: 4, truncated: false,
      entries: [{ index: 0, rva: subject.beginRva }] } };
    const resolve = createEhPersonalityResolver(image, null,
      [{ rva: subject.beginRva, ordinal: 1, names: [name] }]);
    const parsed = await analyzeX86Eh(image, resolve, lc);
    assert.equal(parsed.records[0]?.registration, name);
    assert.equal(parsed.records[0]?.scopes, undefined);
    assert.equal(parsed.records[0]?.functionInfo, undefined);
  });
}

void test("x86 confirmed FH3 stub with malformed FuncInfo reports uncertainty", async () => {
  const subject = absoluteFh3Fixture();
  subject.builder.patchUint32(subject.stub, 1, 0xffffffff);
  const { image, lc, resolve } = x86Subject(subject);
  const parsed = await analyzeX86Eh(image, resolve, lc);
  assert.deepEqual(parsed.records, []);
  assert.match(parsed.warnings[0] ?? "", /FuncInfo.*not validated/);
});

void test("x86 exact stub permits MSVC's two NOP bytes", async () => {
  const subject = absoluteFh3Fixture();
  subject.builder.bytes.copyWithin(subject.builder.offsetOf(subject.stub + 2),
    subject.builder.offsetOf(subject.stub), subject.builder.offsetOf(subject.stub + 10));
  subject.builder.patchByte(subject.stub, 0x90);
  subject.builder.patchByte(subject.stub + 1, 0x90);
  subject.builder.patchInt32(subject.stub, 8, subject.handlerRva - subject.stub - 12);
  const { image, lc, resolve } = x86Subject(subject);
  assert.equal((await analyzeX86Eh(image, resolve, lc)).records.length, 1);
});

void test("x86 missing, malformed and incomplete SafeSEH tables supply no evidence", async () => {
  const subject = absoluteFh3Fixture();
  const { image, lc, resolve } = x86Subject(subject);
  assert.deepEqual(await analyzeX86Eh(image, resolve), { records: [], warnings: [] });
  lc.tables!.safeSehHandler!.truncated = true;
  assert.deepEqual(await analyzeX86Eh(image, resolve, lc), { records: [], warnings: [] });
});

for (const [offset, byte] of [[0, 0xc3], [5, 0xc3]]) {
  void test(`x86 stub rejects an instruction mismatch at ${offset}`, async () => {
    const subject = absoluteFh3Fixture();
    subject.builder.patchByte(subject.stub + offset!, byte!);
    const { image, lc, resolve } = x86Subject(subject);
    assert.deepEqual(await analyzeX86Eh(image, resolve, lc), { records: [], warnings: [] });
  });
}

void test("x86 stub requires an executable complete sequence and the correct personality", async () => {
  const subject = absoluteFh3Fixture();
  const { image, lc } = x86Subject(subject);
  assert.deepEqual(await analyzeX86Eh(image, async () => null, lc), { records: [], warnings: [] });
  lc.tables!.safeSehHandler!.entries[0]!.rva = subject.iatRva;
  assert.deepEqual(await analyzeX86Eh(image, async () => null, lc), { records: [], warnings: [] });
  lc.tables!.safeSehHandler!.entries[0]!.rva = subject.stub;
  image.read = async () => null;
  assert.deepEqual(await analyzeX86Eh(image, async () => null, lc), { records: [], warnings: [] });
});
