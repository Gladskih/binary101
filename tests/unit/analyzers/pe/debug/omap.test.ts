import assert from "node:assert/strict";
import { test } from "node:test";
import { parseOmapInfo } from "../../../../../analyzers/pe/debug/omap.js";
import { createOmapPayload, createOmapSubject } from "../../../../fixtures/pe-omap.js";
import { createExtraDebugPayloadSubject } from "../../../../fixtures/pe-debug-extra-payloads.js";
import { createPeRvaFragments } from "../../../../helpers/pe-rva-fragments.js";

const parseSubject = async (payload: Uint8Array, size = payload.length) => {
  const subject = createExtraDebugPayloadSubject(payload, size);
  const warnings: string[] = [];
  const result = await parseOmapInfo(subject.file, subject.file.size, value => value,
    0, subject.offset, size, message => warnings.push(message));
  return { result, warnings };
};

void test("OMAP preserves unsigned little-endian RVAs, zero targets and file order", async () => {
  const pairs = [[0, 0], [0x12345678, 0xfedcba98], [0xffffffff, 0]] as const;
  const { result, warnings } = await parseSubject(createOmapPayload(pairs));

  assert.deepEqual(result, { records: pairs.map(([rva, rvaTo]) => ({ rva, rvaTo })) });
  assert.deepEqual(warnings, []);
});

void test("OMAP reads an RVA-only payload", async () => {
  const subject = createOmapSubject();
  const warnings: string[] = [];
  const result = await parseOmapInfo(subject.file, subject.file.size, value => value,
    subject.offset, 0, subject.declaredSize, message => warnings.push(message));

  assert.equal(result?.records.length, 3);
  assert.deepEqual(warnings, []);
});

void test("OMAP prefers the file pointer to an unmapped RVA", async () => {
  const subject = createOmapSubject();
  const warnings: string[] = [];
  const result = await parseOmapInfo(subject.file, subject.file.size, () => null,
    1, subject.offset, subject.declaredSize, message => warnings.push(message));

  assert.equal(result?.records.length, 3);
  assert.deepEqual(warnings, []);
});

void test("OMAP keeps whole records before a partial record", async () => {
  const { result, warnings } = await parseSubject(
    new Uint8Array([...createOmapPayload([[1, 2]]), 0xff]));

  assert.deepEqual(result, { records: [{ rva: 1, rvaTo: 2 }] });
  assert.deepEqual(warnings, ["OMAP debug entry has trailing bytes after whole records."]);
});

void test("OMAP handles a payload smaller than one record", async () => {
  const { result, warnings } = await parseSubject(new Uint8Array(7));

  assert.deepEqual(result, { records: [] });
  assert.deepEqual(warnings, ["OMAP debug entry has trailing bytes after whole records."]);
});

void test("OMAP reports an empty table", async () => {
  const { result, warnings } = await parseSubject(new Uint8Array());

  assert.deepEqual(result, { records: [] });
  assert.deepEqual(warnings, ["OMAP debug entry is empty."]);
});

void test("OMAP bounds reads by the file size", async () => {
  const { result, warnings } = await parseSubject(createOmapPayload([[1, 2]]), 0xffffffff);

  assert.deepEqual(result, { records: [{ rva: 1, rvaTo: 2 }] });
  assert.deepEqual(warnings, ["OMAP debug entry is shorter than its declared SizeOfData."]);
});

void test("OMAP warns on duplicate and descending keys without reordering records", async () => {
  const pairs = [[2, 5], [2, 6], [1, 7], [0, 8]] as const;
  const { result, warnings } = await parseSubject(createOmapPayload(pairs));

  assert.deepEqual(result?.records, pairs.map(([rva, rvaTo]) => ({ rva, rvaTo })));
  assert.deepEqual(warnings, ["OMAP input RVAs are not strictly increasing; mapping is ambiguous."]);
});

for (const pointer of [-1, 0, 0xffffffff]) {
  void test(`OMAP rejects unavailable payload pointer ${pointer}`, async () => {
    const subject = createOmapSubject();
    const warnings: string[] = [];
    const result = await parseOmapInfo(subject.file, subject.file.size, () => null,
      0, pointer, subject.declaredSize, message => warnings.push(message));

    assert.equal(result, null);
    assert.equal(warnings.length, 1);
  });
}

void test("OMAP reads large tables in bounded chunks and validates across chunk boundaries", async () => {
  // Cross the shared reader's 64 KiB window (8192 OMAP records).
  const pairs = Array.from({ length: 8193 }, (_, index) => [index, index + 1] as const);
  pairs[8192] = [8191, 0];
  const { result, warnings } = await parseSubject(createOmapPayload(pairs));

  assert.equal(result?.records.length, pairs.length);
  assert.deepEqual(result?.records.at(-1), { rva: 8191, rvaTo: 0 });
  assert.deepEqual(warnings, ["OMAP input RVAs are not strictly increasing; mapping is ambiguous."]);
});

for (const size of [-1, 0.5, NaN, Infinity, 0x100000000]) {
  void test(`OMAP rejects invalid declared size ${size}`, async () => {
    const { result, warnings } = await parseSubject(createOmapPayload([[1, 2]]), size);

    assert.equal(result, null);
    assert.deepEqual(warnings, ["OMAP debug entry has an invalid offset or size."]);
  });
}

void test("OMAP reassembles a record split between noncontiguous RVA fragments", async () => {
  const fixture = createPeRvaFragments(0x1000, createOmapPayload([[1, 2], [3, 4]]), 5);
  const warnings: string[] = [];
  const result = await parseOmapInfo(fixture.reader, fixture.reader.size, fixture.mapping,
    0x1000, 0, 16, message => warnings.push(message));

  assert.deepEqual(result, { records: [{ rva: 1, rvaTo: 2 }, { rva: 3, rvaTo: 4 }] });
  assert.deepEqual(warnings, []);
});

void test("OMAP stops at a mapping gap", async () => {
  const subject = createOmapSubject();
  const warnings: string[] = [];
  const result = await parseOmapInfo(subject.file, subject.file.size,
    value => value < subject.offset + 8 ? value : null,
    subject.offset, 0, subject.declaredSize, message => warnings.push(message));

  assert.deepEqual(result, { records: [{ rva: 0, rvaTo: 0 }] });
  assert.deepEqual(warnings, ["OMAP debug entry is shorter than its declared SizeOfData."]);
});

void test("OMAP preserves complete records on an unexpectedly short read", async () => {
  const subject = createOmapSubject();
  const warnings: string[] = [];
  const result = await parseOmapInfo({
    size: subject.file.size,
    read: offset => subject.file.read(offset, 9),
    readBytes: (offset, size) => subject.file.readBytes(offset, size)
  }, subject.file.size, value => value, 0, subject.offset, subject.declaredSize,
  message => warnings.push(message));

  assert.deepEqual(result, { records: [{ rva: 0, rvaTo: 0 }] });
  assert.deepEqual(warnings, ["OMAP debug payload is truncated while reading records."]);
});

void test("OMAP does not read beyond the last complete record or issue empty reads", async () => {
  const subject = createExtraDebugPayloadSubject(new Uint8Array(7));
  const warnings: string[] = [];
  const result = await parseOmapInfo({
    size: subject.file.size,
    read: () => assert.fail("No complete record is available to read"),
    readBytes: () => assert.fail("No complete record is available to read")
  }, subject.file.size, value => value, 0, subject.offset, subject.declaredSize,
  message => warnings.push(message));

  assert.deepEqual(result, { records: [] });
  assert.deepEqual(warnings, ["OMAP debug entry has trailing bytes after whole records."]);
});
