import assert from "node:assert/strict";
import { test } from "node:test";
import { readFh4Handlers, readFh4IpStates, readFh4TryBlocks, readFh4Unwind }
  from "../../../../../analyzers/pe/msvc-eh/fh4-maps.js";
import { createEhImage } from "../../../../../analyzers/pe/msvc-eh/image.js";
import { createEhFixture, addFh4 } from "../../../../fixtures/pe-msvc-eh.js";

const mapFixture = (bytes: number[]) => {
  const subject = createEhFixture();
  const rva = subject.builder.allocateData(bytes.length, 1);
  subject.builder.bytes.set(bytes, subject.builder.offsetOf(rva));
  subject.builder.truncateAtRva(rva + bytes.length);
  const fixture = subject.builder.build();
  return { ...subject, rva, image: createEhImage(fixture.file, fixture.core) };
};

for (const [encoded, expected] of [[10, 0], [12, 0], [14, 0]] as const) {
  void test(`FH4 unwind type ${(encoded / 2) & 3} validates a direct action`, async () => {
    // Handler at RVA 0x1010; a one-state map returns to the implicit state -1.
    const subject = mapFixture([2, encoded, 0x10, 0x10, 0, 0, 0]);
    const parsed = await readFh4Unwind(subject.image, subject.rva);
    assert.deepEqual(parsed, [{ toState: -1, actionRva: subject.catchRva + expected }]);
  });
}

void test("FH4 unwind offsets refer to exact prior entry starts", async () => {
  const subject = mapFixture([4, 8, 8]);
  assert.deepEqual(await readFh4Unwind(subject.image, subject.rva),
    [{ toState: -1, actionRva: 0 }, { toState: 0, actionRva: 0 }]);
  assert.deepEqual(await readFh4Unwind(subject.image, 0), []);
});

void test("shared FH4 unwind maps are decoded once per image regardless of function-relative consumers", async () => {
  const subject = mapFixture([4, 8, 8]);
  const first = readFh4Unwind(subject.image, subject.rva);
  const second = readFh4Unwind(subject.image, subject.rva);
  assert.equal(first, second);
  assert.deepEqual(await first, [{ toState: -1, actionRva: 0 }, { toState: 0, actionRva: 0 }]);
});

for (const bytes of [[0], [2, 0], [2, 14, 0, 0, 0, 0], [4, 14, 0x10, 0x10, 0, 0, 16], [15, 0]]) {
  void test(`FH4 unwind rejects malformed transition bytes ${bytes.join(",")}`, async () => {
    const subject = mapFixture(bytes);
    assert.equal(await readFh4Unwind(subject.image, subject.rva), null);
  });
}

void test("FH4 IP maps preserve delta addresses and EHstate+1", async () => {
  const subject = mapFixture([4, 0, 0, 8, 2]);
  assert.deepEqual(await readFh4IpStates(subject.image, subject.rva, subject.beginRva, 1),
    [{ ipRva: subject.beginRva, state: -1 }, { ipRva: subject.beginRva + 4, state: 0 }]);
});

for (const bytes of [[0], [2, 0, 4], [4, 0, 0, 0, 0], [2, 15, 255, 255, 255, 255, 0], [2, 0]]) {
  void test(`FH4 IP map rejects invalid encoding ${bytes.join(",")}`, async () => {
    const subject = mapFixture(bytes);
    assert.equal(await readFh4IpStates(subject.image, subject.rva, subject.beginRva, 1), null);
  });
}

for (const header of [0x40, 0x80, 0x30]) {
  void test(`FH4 handler rejects reserved header 0x${header.toString(16)}`, async () => {
    const subject = mapFixture([2, header, 0x10, 0x10, 0, 0]);
    assert.equal(await readFh4Handlers(subject.image, subject.rva, subject.beginRva), null);
  });
}

void test("FH4 handler reads optional adjectives and catch-object displacement", async () => {
  const subject = mapFixture([2, 5, 2, 0, 0x10, 0x10, 0, 0]);
  assert.deepEqual(await readFh4Handlers(subject.image, subject.rva, subject.beginRva),
    [{ handlerRva: subject.catchRva, typeDescriptorRva: 0, continuationRvas: [] }]);
});

void test("FH4 handler reads two absolute continuation RVAs", async () => {
  const subject = mapFixture([2, 0x28, 0x10, 0x10, 0, 0, 4, 0x10, 0, 0, 8, 0x10, 0, 0]);
  assert.deepEqual((await readFh4Handlers(subject.image, subject.rva, subject.beginRva))?.[0]?.continuationRvas,
    [subject.beginRva + 4, subject.beginRva + 8]);
});

for (const bytes of [[0], [2, 0, 0, 0, 0, 0], [2, 0x10, 0x10, 0x10, 0, 0, 15, 255, 255, 255, 255]]) {
  void test(`FH4 handler rejects empty maps and non-code targets ${bytes.join(",")}`, async () => {
    const subject = mapFixture(bytes);
    assert.equal(await readFh4Handlers(subject.image, subject.rva, subject.beginRva), null);
  });
}

void test("FH4 handler validates a typed catch descriptor", async () => {
  const subject = createEhFixture();
  const { handlerMapRva } = addFh4(subject);
  const type = subject.builder.addType(".H");
  subject.builder.patchByte(handlerMapRva + 1, 2);
  subject.builder.patchUint32(handlerMapRva, 2, type.rva);
  subject.builder.patchUint32(handlerMapRva, 6, subject.catchRva);
  const fixture = subject.builder.build();
  const handlers = await readFh4Handlers(createEhImage(fixture.file, fixture.core), handlerMapRva, subject.beginRva);
  assert.equal(handlers?.[0]?.typeDescriptorRva, type.rva);
});

void test("FH4 try map distinguishes absent and advertised empty maps", async () => {
  const subject = mapFixture([0]);
  assert.deepEqual(await readFh4TryBlocks(subject.image, 0, 0, subject.beginRva), []);
  assert.equal(await readFh4TryBlocks(subject.image, subject.rva, 0, subject.beginRva), null);
});

for (const [offset, value] of [[1, 4], [2, 4], [3, 4], [4, 0xffffffff]]) {
  void test(`FH4 try map rejects state or handler reference at ${offset}`, async () => {
    const subject = createEhFixture();
    const { tryMapRva } = addFh4(subject);
    subject.builder.patchByte(tryMapRva + offset!, value! & 255);
    const fixture = subject.builder.build();
    assert.equal(await readFh4TryBlocks(createEhImage(fixture.file, fixture.core), tryMapRva, 2,
      subject.beginRva), null);
  });
}

// UWMap4's low two bits distinguish object/object-pointer displacements from funclets.
for (const bytes of [[4, 10, 0x10, 0x10, 0, 0, 0, 48],
  [4, 12, 0x10, 0x10, 0, 0, 0, 48], [4, 14, 0x10, 0x10, 0, 0, 40]]) {
  void test(`FH4 unwind entry boundaries preserve the following state for type ${bytes[1]}`, async () => {
    const subject = mapFixture(bytes);
    assert.deepEqual(await readFh4Unwind(subject.image, subject.rva),
      [{ toState: -1, actionRva: subject.catchRva }, { toState: 0, actionRva: 0 }]);
  });
}

void test("three FH4 continuations are reserved even when all encoded targets would be valid", async () => {
  const subject = mapFixture([2, 0x30, 0x10, 0x10, 0, 0, 0, 0, 0]);
  assert.equal(await readFh4Handlers(subject.image, subject.rva, subject.beginRva), null);
});

void test("FH4 try high state cannot equal its catch high state", async () => {
  const subject = createEhFixture();
  const { tryMapRva } = addFh4(subject);
  subject.builder.patchByte(tryMapRva + 2, 2); // tryHigh=1, catchHigh=1; state budget=3.
  const fixture = subject.builder.build();
  assert.equal(await readFh4TryBlocks(createEhImage(fixture.file, fixture.core), tryMapRva, 3,
    subject.beginRva), null);
});
