import assert from "node:assert/strict";
import { test } from "node:test";
import { ehCodeRva, ehMetadataRva, readEhTable, validCatchType, validEhState,
  validateEhFunctionLinks } from "../../../../../analyzers/pe/msvc-eh/validation.js";
import { createEhImage } from "../../../../../analyzers/pe/msvc-eh/image.js";
import { createEhFixture } from "../../../../fixtures/pe-msvc-eh.js";

void test("EH table reads are bounded per entry and reject invalid indices and counts", async () => {
  const subject = createEhFixture();
  const rva = subject.builder.allocateData(16);
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  const table = readEhTable(image, rva, 2, 8);
  assert.ok(table);
  assert.equal((await table.read(1))?.byteLength, 8);
  assert.equal(await table.read(2), null);
  assert.equal(await table.read(-1), null);
  assert.equal(readEhTable(image, rva, -1, 8), null);
  assert.equal(readEhTable(image, rva, 0, 8), null);
  assert.equal(readEhTable(image, 0, 1, 8), null);
  assert.equal(readEhTable(image, rva, 0xffffffff, 8), null);
  assert.equal(readEhTable(image, rva + 1, 1, 8), null);
  assert.equal(readEhTable(image, rva, 1, 0), null);
  assert.equal(readEhTable(image, 0, 0, 8)?.count, 0);
});

for (const [state, count, expected] of [[-1, 0, true], [-2, 5, false], [0, 1, true], [1, 1, false]] as const) {
  void test(`EH state ${state} validates against ${count} states`, () => {
    assert.equal(validEhState(state, count), expected);
  });
}

void test("catch type validation accepts fundamental names and memoizes per image", async () => {
  const subject = createEhFixture();
  const rva = subject.builder.allocateData(20, 8);
  subject.builder.patchBigUint64(rva, 0x180002000n);
  subject.builder.bytes.set([0x2e, 0x48, 0], subject.builder.offsetOf(rva + 16)); // MSVC int: .H.
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  const original = image.read;
  let reads = 0;
  image.read = (start, size) => { reads++; return original(start, size); };
  assert.equal(await validCatchType(image, rva), true);
  const firstReads = reads;
  assert.equal(await validCatchType(image, rva), true);
  assert.equal(reads, firstReads);
  assert.equal(await validCatchType(image, 0), true);
});

void test("metadata pointers preserve preferred VA subtraction and Thumb normalization", () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  assert.equal(ehMetadataRva(image, 0x2000), 0x2000);
  image.core.coff.Machine = 0x14c;
  image.core.opt.ImageBase = 0x400000n;
  assert.equal(ehMetadataRva(image, 0x402000), 0x2000);
  assert.equal(ehMetadataRva(image, 0), 0);
  image.core.coff.Machine = 0x1c4;
  assert.equal(ehCodeRva(image, 0x1001), 0x1000);
});

void test("function association requires actual IP entries, executable starts and owner evidence", () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  const info = { rva: 0x2000, version: 3 as const, unwindActions: [], tryBlocks: [],
    ipStates: [{ ipRva: subject.beginRva, state: -1 }] };
  assert.equal(validateEhFunctionLinks(info, rva => rva === subject.beginRva), true);
  assert.equal(validateEhFunctionLinks(info, () => false), false);
  assert.equal(validateEhFunctionLinks(info, rva => rva === subject.catchRva), false);
  assert.equal(validateEhFunctionLinks(info, rva => image.code(rva) && rva === 0x2000), false);
  assert.equal(validateEhFunctionLinks({ ...info, ipStates: [] }, () => true), false);
});

for (const bytes of [[0, 0], [0x2e, 0], [0x2e, 0x20, 0], [0x2e, 0x7f, 0]]) {
  void test(`catch descriptor rejects noncanonical name bytes ${bytes.join(",")}`, async () => {
    const subject = createEhFixture();
    const rva = subject.builder.allocateData(16 + bytes.length, 8);
    subject.builder.patchBigUint64(rva, 0x180002000n);
    subject.builder.bytes.set(bytes, subject.builder.offsetOf(rva + 16));
    const fixture = subject.builder.build();
    assert.equal(await validCatchType(createEhImage(fixture.file, fixture.core), rva), false);
  });
}

void test("unterminated catch names and nonzero spare pointers are not accepted", async () => {
  const subject = createEhFixture();
  const rva = subject.builder.allocateData(20, 8);
  subject.builder.patchBigUint64(rva, 0x180002000n);
  subject.builder.bytes.set([0x2e, 0x48, 0x48, 0x48], subject.builder.offsetOf(rva + 16));
  subject.builder.truncateAtRva(rva + 20);
  const fixture = subject.builder.build();
  assert.equal(await validCatchType(createEhImage(fixture.file, fixture.core), rva), false);
  subject.builder.patchBigUint64(rva + 8, 0x100000000n);
  const spare = subject.builder.build();
  assert.equal(await validCatchType(createEhImage(spare.file, spare.core), rva), false);
});

void test("32-bit catch descriptors use two four-byte pointers", async () => {
  const subject = createEhFixture();
  const rva = subject.builder.allocateData(12);
  subject.builder.patchUint32(rva, 0, 0x402000);
  subject.builder.bytes.set([0x2e, 0x48, 0], subject.builder.offsetOf(rva + 8));
  const fixture = subject.builder.build();
  fixture.core.coff.Machine = 0x14c;
  fixture.core.opt = { ...fixture.core.opt, Magic: 0x10b, BaseOfData: 0x2000 };
  assert.equal(await validCatchType(createEhImage(fixture.file, fixture.core), rva), true);
});

// TypeDescriptor fields and spelling follow MSVC ehdata.h / MicrosoftCXXABI.
for (const [vftable, spare, prefix, expected] of [
  [0n, 0n, 0x2e, false], [0x100000000n, 0n, 0x2e, true],
  [0x180002000n, 1n, 0x2e, false], [0x180002000n, 0x100000000n, 0x2e, false],
  [0x180002000n, 0n, 0x3f, false]
] as const) {
  void test(`catch descriptor header validates ${vftable}/${spare}/${prefix}`, async () => {
    const subject = createEhFixture();
    const rva = subject.builder.allocateData(20, 8);
    subject.builder.patchBigUint64(rva, vftable);
    subject.builder.patchBigUint64(rva + 8, spare);
    subject.builder.bytes.set([prefix, 0x48, 0], subject.builder.offsetOf(rva + 16));
    const fixture = subject.builder.build();
    assert.equal(await validCatchType(createEhImage(fixture.file, fixture.core), rva), expected);
  });
}

void test("a catch descriptor requires the entire readable header", async () => {
  const subject = createEhFixture();
  const rva = subject.builder.allocateData(18, 8);
  subject.builder.truncateAtRva(rva + 17);
  const fixture = subject.builder.build();
  assert.equal(await validCatchType(createEhImage(fixture.file, fixture.core), rva), false);
});

void test("table count fits the stride and every IP entry needs independent coverage", () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  assert.equal(readEhTable(image, subject.dataRva, image.available(subject.dataRva), 8), null);
  assert.equal(ehCodeRva(image, subject.beginRva + 1), subject.beginRva + 1);
  assert.equal(validateEhFunctionLinks({ rva: subject.dataRva, version: 3, unwindActions: [], tryBlocks: [],
    ipStates: [{ ipRva: subject.beginRva, state: -1 }, { ipRva: subject.catchRva, state: 0 }] },
  rva => rva === subject.beginRva), false);
});
