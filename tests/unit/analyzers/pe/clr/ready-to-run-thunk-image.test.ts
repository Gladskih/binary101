import assert from "node:assert/strict";
import test from "node:test";
import { decodeReadyToRunThunks, collectReadyToRunThunkRvas } from
  "../../../../../analyzers/pe/clr/ready-to-run-thunk-image.js";
import { thunkImageFixture } from "../../../../helpers/ready-to-run-thunk-image-fixture.js";

void test("decodes once and seeds thunk instruction starts, excluding their data cells", async context => {
  const fixture = thunkImageFixture();
  fixture.pe.clr!.readyToRun!.sections.push({ ...fixture.section });
  const reads = context.mock.method(fixture.reader, "read");

  await decodeReadyToRunThunks(fixture.reader, fixture.pe);
  await decodeReadyToRunThunks(fixture.reader, fixture.pe);

  assert.deepEqual(collectReadyToRunThunkRvas(fixture.pe, fixture.reader.size, fixture.issues), [0x100, 0x108]);
  assert.equal(fixture.section.decoded?.kind, "thunks");
  assert.equal(fixture.section.decoded, fixture.pe.clr!.readyToRun!.sections[1]!.decoded);
  assert.equal(reads.mock.callCount(), 1);
  assert.deepEqual(fixture.issues, []);
});

void test("different thunk ranges do not alias each other's decoded bodies", async () => {
  const fixture = thunkImageFixture();
  const other = { type: 106, name: "DelayLoadMethodCallThunks", rva: 0x108, size: 6 };
  fixture.pe.clr!.readyToRun!.sections.push(other);

  await decodeReadyToRunThunks(fixture.reader, fixture.pe);

  assert.notEqual(fixture.section.decoded, fixture.pe.clr!.readyToRun!.sections[1]!.decoded);
  assert.deepEqual(fixture.pe.clr!.readyToRun!.sections[1]!.decoded,
    { kind: "thunks", entries: [{ rva: 0x108, size: 6, kind: "eager", helperCellRva: 0x3000 }] });
});

void test("accepts exact image/raw boundaries but rejects virtual tails and unmapped bytes", async () => {
  const fixture = thunkImageFixture();
  await decodeReadyToRunThunks(fixture.reader, fixture.pe);
  fixture.pe.opt.SizeOfImage = 0x10e;
  fixture.pe.sections[0]!.sizeOfRawData = 14;

  assert.deepEqual(collectReadyToRunThunkRvas(fixture.pe, fixture.reader.size, fixture.issues), [0x100, 0x108]);
  fixture.pe.opt.SizeOfImage--;
  assert.deepEqual(collectReadyToRunThunkRvas(fixture.pe, fixture.reader.size, fixture.issues), [0x100]);
  assert.deepEqual(collectReadyToRunThunkRvas(fixture.pe, 0x100, fixture.issues), []);
});

void test("zero and invalid instruction RVAs cannot become seeds", () => {
  const fixture = thunkImageFixture();
  fixture.pe.sections[0]!.virtualAddress = 0;
  fixture.pe.sections[0]!.pointerToRawData = 0;
  fixture.section.decoded = { kind: "thunks", entries: [
    { rva: 0, size: 6, kind: "eager", helperCellRva: null },
    { rva: 0x100, size: -1, kind: "eager", helperCellRva: null }
  ] };

  assert.deepEqual(collectReadyToRunThunkRvas(fixture.pe, fixture.reader.size, fixture.issues), []);
  assert.equal(fixture.issues.length, 2);
});

void test("seeds only physically backed executable code and visibly rejects invalid bodies", async () => {
  const fixture = thunkImageFixture();
  await decodeReadyToRunThunks(fixture.reader, fixture.pe);
  fixture.pe.sections[0]!.sizeOfRawData = 9;

  assert.deepEqual(collectReadyToRunThunkRvas(fixture.pe, fixture.reader.size, fixture.issues), [0x100]);
  fixture.pe.sections[0]!.characteristics = 0;
  assert.deepEqual(collectReadyToRunThunkRvas(fixture.pe, fixture.reader.size, fixture.issues), []);
  assert.match(fixture.issues.join(), /executable/);
});

void test("works for CLR-free composite images and skips absent or unrecognized headers", async () => {
  const fixture = thunkImageFixture();
  fixture.pe.readyToRun = fixture.pe.clr!.readyToRun!;
  fixture.pe.clr = null;

  await decodeReadyToRunThunks(fixture.reader, fixture.pe);

  assert.deepEqual(collectReadyToRunThunkRvas(fixture.pe, fixture.reader.size, fixture.issues), [0x100, 0x108]);
  fixture.pe.readyToRun!.status = "ngen";
  await decodeReadyToRunThunks(fixture.reader, fixture.pe);
  assert.deepEqual(collectReadyToRunThunkRvas(fixture.pe, fixture.reader.size, fixture.issues), []);
  delete fixture.pe.readyToRun;
  await decodeReadyToRunThunks(fixture.reader, fixture.pe);
  assert.deepEqual(collectReadyToRunThunkRvas(fixture.pe, fixture.reader.size, fixture.issues), []);
});
