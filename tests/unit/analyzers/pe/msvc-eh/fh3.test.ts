import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFh3 } from "../../../../../analyzers/pe/msvc-eh/fh3.js";
import { createEhImage } from "../../../../../analyzers/pe/msvc-eh/image.js";
import { createEhFixture, addFh3 } from "../../../../fixtures/pe-msvc-eh.js";

void test("FH3 validates complete state, try, handler and IP tables", async () => {
  const subject = createEhFixture();
  const { infoRva } = addFh3(subject);
  const fixture = subject.builder.build();
  const parsed = await parseFh3(createEhImage(fixture.file, fixture.core), infoRva);
  assert.equal(parsed?.version, 3);
  assert.deepEqual(parsed?.unwindActions, [{ toState: -1, actionRva: 0 }, { toState: -1, actionRva: 0 }]);
  assert.deepEqual(parsed?.tryBlocks[0]?.handlers, [{ handlerRva: subject.catchRva,
    typeDescriptorRva: 0, continuationRvas: [] }]);
});

for (const [field, value] of [[0, 0x19930523], [4, 0xffffffff], [8, 0], [12, 0xffffffff],
  [20, 0], [24, 0xffffffff], [32, 1], [36, 8]] as const) {
  void test(`FH3 rejects unsupported or contradictory header field ${field}`, async () => {
    const subject = createEhFixture();
    const { infoRva } = addFh3(subject);
    subject.builder.patchUint32(infoRva, field, value);
    const fixture = subject.builder.build();
    assert.equal(await parseFh3(createEhImage(fixture.file, fixture.core), infoRva), null);
  });
}

void test("FH3 rejects forward unwind transitions", async () => {
  const subject = createEhFixture();
  const { infoRva, unwindRva } = addFh3(subject);
  subject.builder.patchInt32(unwindRva, 0, 0);
  const fixture = subject.builder.build();
  assert.equal(await parseFh3(createEhImage(fixture.file, fixture.core), infoRva), null);
});

for (const [map, offset, value] of [
  ["unwindRva", 4, 0x2000], ["tryMapRva", 0, 0xffffffff], ["tryMapRva", 4, 1],
  ["tryMapRva", 8, 2], ["tryMapRva", 12, 0], ["tryMapRva", 16, 0xffffffff],
  ["handlerMapRva", 12, 0x2000], ["handlerMapRva", 4, 0xffffffff], ["ipMapRva", 4, 2],
  ["ipMapRva", 0, 0x2000]
] as const) {
  void test(`FH3 rejects invalid ${map} field ${offset}`, async () => {
    const subject = createEhFixture();
    const maps = addFh3(subject);
    subject.builder.patchUint32(maps[map], offset, value);
    const fixture = subject.builder.build();
    assert.equal(await parseFh3(createEhImage(fixture.file, fixture.core), maps.infoRva), null);
  });
}

void test("FH3 validates typed catches, real unwind actions and caches shared metadata", async () => {
  const subject = createEhFixture();
  const { infoRva, handlerMapRva, unwindRva } = addFh3(subject);
  const type = subject.builder.addType(".H");
  subject.builder.patchUint32(handlerMapRva, 4, type.rva);
  subject.builder.patchUint32(unwindRva, 4, subject.catchRva);
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  const parsed = parseFh3(image, infoRva);
  assert.equal(parsed, parseFh3(image, infoRva));
  assert.equal((await parsed)?.tryBlocks[0]?.handlers[0]?.typeDescriptorRva, type.rva);
});

void test("FH3 rejects unsorted and repeated IP addresses", async () => {
  const subject = createEhFixture();
  const { infoRva } = addFh3(subject);
  const ips = subject.builder.allocateData(16);
  subject.builder.patchUint32(ips, 0, subject.catchRva);
  subject.builder.patchInt32(ips, 4, -1);
  subject.builder.patchUint32(ips, 8, subject.beginRva);
  subject.builder.patchInt32(ips, 12, -1);
  subject.builder.patchUint32(infoRva, 20, 2);
  subject.builder.patchUint32(infoRva, 24, ips);
  const fixture = subject.builder.build();
  assert.equal(await parseFh3(createEhImage(fixture.file, fixture.core), infoRva), null);
});

void test("FH3 rejects a truncated header and misaligned FuncInfo address", async () => {
  const subject = createEhFixture();
  const { infoRva } = addFh3(subject);
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  assert.equal(await parseFh3(image, 0xffffffff), null);
  assert.equal(await parseFh3(image, infoRva + 1), null);
});

void test("FH3 handler arrays use twenty-byte Win64 entries and preserve nonzero states", async () => {
  const subject = createEhFixture();
  const { infoRva, tryMapRva, ipMapRva } = addFh3(subject);
  const unwind = subject.builder.allocateData(24);
  subject.builder.patchInt32(unwind, 0, -1);
  subject.builder.patchInt32(unwind, 16, 1);
  subject.builder.patchUint32(infoRva, 4, 3);
  subject.builder.patchUint32(infoRva, 8, unwind);
  const handlers = subject.builder.allocateData(40);
  subject.builder.patchUint32(handlers, 12, subject.catchRva);
  subject.builder.patchUint32(handlers, 32, subject.handlerRva);
  subject.builder.patchUint32(tryMapRva, 12, 2);
  subject.builder.patchUint32(tryMapRva, 16, handlers);
  subject.builder.patchInt32(tryMapRva, 0, 1);
  subject.builder.patchInt32(tryMapRva, 4, 1);
  subject.builder.patchInt32(tryMapRva, 8, 2);
  subject.builder.patchInt32(ipMapRva, 4, 2);
  subject.builder.patchUint32(infoRva, 36, 7); // All three supported EHFlags, ehdata.h.
  const fixture = subject.builder.build();
  const parsed = await parseFh3(createEhImage(fixture.file, fixture.core), infoRva);
  assert.deepEqual(parsed?.tryBlocks[0]?.handlers.map(handler => handler.handlerRva),
    [subject.catchRva, subject.handlerRva]);
  assert.equal(parsed?.unwindActions[2]?.toState, 1);
  assert.equal(parsed?.ipStates[0]?.state, 2);
});

void test("a try block cannot advertise zero handlers with a null handler map", async () => {
  const subject = createEhFixture();
  const { infoRva, tryMapRva } = addFh3(subject);
  subject.builder.patchUint32(tryMapRva, 12, 0);
  subject.builder.patchUint32(tryMapRva, 16, 0);
  const fixture = subject.builder.build();
  assert.equal(await parseFh3(createEhImage(fixture.file, fixture.core), infoRva), null);
});

void test("repeated FH3 IP entries are invalid even when their states agree", async () => {
  const subject = createEhFixture();
  const { infoRva } = addFh3(subject);
  const ips = subject.builder.allocateData(16);
  subject.builder.patchUint32(ips, 0, subject.beginRva);
  subject.builder.patchInt32(ips, 4, -1);
  subject.builder.patchUint32(ips, 8, subject.beginRva);
  subject.builder.patchInt32(ips, 12, -1);
  subject.builder.patchUint32(infoRva, 20, 2);
  subject.builder.patchUint32(infoRva, 24, ips);
  const fixture = subject.builder.build();
  assert.equal(await parseFh3(createEhImage(fixture.file, fixture.core), infoRva), null);
});

void test("different FH3 records do not collide in the metadata cache", async () => {
  const subject = createEhFixture();
  const first = addFh3(subject);
  const second = addFh3(subject);
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  assert.equal((await parseFh3(image, first.infoRva))?.rva, first.infoRva);
  assert.equal((await parseFh3(image, second.infoRva))?.rva, second.infoRva);
});
