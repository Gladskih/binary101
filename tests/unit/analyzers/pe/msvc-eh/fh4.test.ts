import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { parseFh4 } from "../../../../../analyzers/pe/msvc-eh/fh4.js";
import { createEhImage } from "../../../../../analyzers/pe/msvc-eh/image.js";
import { createEhFixture, addFh4 } from "../../../../fixtures/pe-msvc-eh.js";

void test("FH4 decodes compressed tables and function-relative continuations", async () => {
  const subject = createEhFixture();
  const { infoRva } = addFh4(subject);
  const fixture = subject.builder.build();
  const parsed = await parseFh4(createEhImage(fixture.file, fixture.core), infoRva, subject.beginRva);
  assert.equal(parsed?.version, 4);
  assert.deepEqual(parsed?.unwindActions, [{ toState: -1, actionRva: 0 }, { toState: -1, actionRva: 0 }]);
  assert.deepEqual(parsed?.tryBlocks[0]?.handlers[0]?.continuationRvas, [subject.beginRva + 8]);
});

void test("FH4 supports BBT and catch-frame optional fields and caches a contribution", async () => {
  const subject = createEhFixture();
  const { unwindRva, tryMapRva, ipMapRva } = addFh4(subject);
  const rva = subject.builder.allocateData(15, 1);
  subject.builder.patchByte(rva, 0x3d); // EHs|try|unwind|BBT|isCatch.
  subject.builder.patchByte(rva + 1, 8); // BBT=4.
  subject.builder.patchUint32(rva, 2, unwindRva);
  subject.builder.patchUint32(rva, 6, tryMapRva);
  subject.builder.patchUint32(rva, 10, ipMapRva);
  subject.builder.patchByte(rva + 14, 16); // Frame offset=8.
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  const first = parseFh4(image, rva, subject.beginRva);
  assert.equal(first, parseFh4(image, rva, subject.beginRva));
  assert.equal((await first)?.version, 4);
});

void test("FH4 supports a valid separated contribution and rejects a missing owner", async () => {
  const subject = createEhFixture();
  const { infoRva, ipMapRva } = addFh4(subject);
  const map = subject.builder.allocateData(9, 1);
  subject.builder.patchByte(map, 2);
  subject.builder.patchUint32(map, 1, subject.beginRva);
  subject.builder.patchUint32(map, 5, ipMapRva);
  subject.builder.patchByte(infoRva, 0x3a);
  subject.builder.patchUint32(infoRva, 9, map);
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  const reads = mock.method(image, "read");
  assert.equal((await parseFh4(image, infoRva, subject.beginRva))?.ipStates[0]?.ipRva, subject.beginRva);
  assert.equal(await parseFh4(image, infoRva, subject.catchRva), null);
  assert.equal(reads.mock.calls.filter(call => call.arguments[0] === ipMapRva).length, 1);
});

for (const field of [1, 5, 9]) {
  void test(`FH4 rejects an invalid referenced map at header offset ${field}`, async () => {
    const subject = createEhFixture();
    const { infoRva } = addFh4(subject);
    subject.builder.patchUint32(infoRva, field, 0);
    const fixture = subject.builder.build();
    assert.equal(await parseFh4(createEhImage(fixture.file, fixture.core), infoRva, subject.beginRva), null);
  });
}

void test("FH4 rejects a truncated header and malformed unwind map", async () => {
  const subject = createEhFixture();
  const { infoRva, unwindRva } = addFh4(subject);
  subject.builder.patchByte(unwindRva + 1, 0); // Self-transition, not an earlier entry.
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  assert.equal(await parseFh4(image, infoRva, subject.beginRva), null);
  assert.equal(await parseFh4(image, 0xffffffff, subject.beginRva), null);
});

void test("FH4 rejects reserved header bits", async () => {
  const subject = createEhFixture();
  const { infoRva } = addFh4(subject);
  subject.builder.patchByte(infoRva, 0xb8); // Reserved bit on an otherwise complete valid header.
  const fixture = subject.builder.build();
  assert.equal(await parseFh4(createEhImage(fixture.file, fixture.core), infoRva, subject.beginRva), null);
});

for (const [flags, expected] of [[0x38, true], [0x39, false]] as const) {
  void test(`FH4 optional catch-frame byte is required exactly when flagged ${flags}`, async () => {
    const subject = createEhFixture();
    const { infoRva } = addFh4(subject);
    subject.builder.patchByte(infoRva, flags);
    subject.builder.truncateAtRva(infoRva + 13); // No catch-frame displacement follows the three RVAs.
    const fixture = subject.builder.build();
    assert.equal((await parseFh4(createEhImage(fixture.file, fixture.core), infoRva, subject.beginRva)) != null,
      expected);
  });
}

void test("separated FH4 contributions cannot repeat an owner's start", async () => {
  const subject = createEhFixture();
  const { infoRva, ipMapRva } = addFh4(subject);
  const map = subject.builder.allocateData(17, 1);
  subject.builder.patchByte(map, 4);
  subject.builder.patchUint32(map, 1, subject.beginRva);
  subject.builder.patchUint32(map, 5, ipMapRva);
  subject.builder.patchUint32(map, 9, subject.beginRva);
  subject.builder.patchUint32(map, 13, ipMapRva);
  subject.builder.patchByte(infoRva, 0x3a);
  subject.builder.patchUint32(infoRva, 9, map);
  const fixture = subject.builder.build();
  assert.equal(await parseFh4(createEhImage(fixture.file, fixture.core), infoRva, subject.beginRva), null);
});

void test("FH4 separated contributions choose their own IP map and validate every referenced map", async () => {
  const subject = createEhFixture();
  const { infoRva, ipMapRva } = addFh4(subject);
  const map = subject.builder.allocateData(17, 1);
  subject.builder.patchByte(map, 4); // Two contribution entries.
  subject.builder.patchUint32(map, 1, subject.beginRva);
  subject.builder.patchUint32(map, 5, ipMapRva);
  subject.builder.patchUint32(map, 9, subject.catchRva);
  subject.builder.patchUint32(map, 13, 0x11ff); // Mapped byte, but not a complete IP map.
  subject.builder.patchByte(infoRva, 0x3a);
  subject.builder.patchUint32(infoRva, 9, map);
  const fixture = subject.builder.build();
  assert.equal(await parseFh4(createEhImage(fixture.file, fixture.core), infoRva, subject.beginRva), null);
});
