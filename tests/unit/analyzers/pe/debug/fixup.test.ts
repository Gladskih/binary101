import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFixupInfo } from "../../../../../analyzers/pe/debug/fixup.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../../../../fixtures/pe-debug-extra-payloads.js";

const payload = (count = 2): Uint8Array => {
  const bytes = new Uint8Array(count * 12);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < count; index++) {
    view.setUint16(index * 12, index + 1, true);
    view.setUint16(index * 12 + 2, 0x8000, true);
    view.setUint32(index * 12 + 4, 0x1000 + index * 4, true);
    view.setUint32(index * 12 + 8, 0x2000 + index * 8, true);
  }
  return bytes;
};

const parse = async (bytes: Uint8Array, declaredSize = bytes.length) => {
  const subject = createExtraDebugPayloadSubject(bytes, declaredSize);
  const issues: string[] = [];
  return { result: await parseFixupInfo(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, declaredSize, issue => issues.push(issue)), issues };
};

void test("FIXUP decodes Microsoft's XFIXUP records without interpreting opaque Extra flags", async () => {
  const { result, issues } = await parse(payload());

  assert.deepEqual(result, { records: [
    { type: 1, extra: 0x8000, rva: 0x1000, targetRva: 0x2000 },
    { type: 2, extra: 0x8000, rva: 0x1004, targetRva: 0x2008 }
  ] });
  assert.deepEqual(issues, []);
});

void test("FIXUP accepts an empty array and retains complete records before trailing data", async () => {
  const empty = await parse(new Uint8Array());
  const trailing = await parse(Uint8Array.from([...payload(), 1]));

  assert.deepEqual(empty.result, { records: [] });
  assert.deepEqual(empty.issues, []);
  assert.equal(trailing.result?.records.length, 2);
  assert.match(trailing.issues.join(" | "), /partial FIXUP record/);
  assert.equal(trailing.issues.length, 1);
});

void test("FIXUP accepts exactly one complete 12-byte record", async () => {
  const { result, issues } = await parse(payload(1));

  assert.equal(result?.records.length, 1);
  assert.deepEqual(issues, []);
});

void test("FIXUP diagnoses payloads smaller than a record and declared truncation", async () => {
  const short = await parse(Uint8Array.of(1));
  const truncated = await parse(payload(), payload().length + 12);

  assert.equal(short.result, null);
  assert.match(short.issues.join(" | "), /smaller/);
  assert.equal(truncated.result?.records.length, 2);
  assert.match(truncated.issues.join(" | "), /shorter.*SizeOfData/);
});

void test("FIXUP bounds every read window and parses records beyond the first window", async () => {
  const subject = createExtraDebugPayloadSubject(payload(5462)); // 65544 bytes crosses the 64 KiB read window.
  const issues: string[] = [];
  const reader = { size: subject.file.size, readBytes: subject.file.readBytes.bind(subject.file),
    read: async (offset: number, size: number) => {
      assert.ok(size <= 65536);
      return subject.file.read(offset, size);
    } };
  const result = await parseFixupInfo(reader, reader.size, identityRvaToOff, 0, subject.offset,
    subject.declaredSize, issue => issues.push(issue));

  assert.equal(result?.records.length, 5462);
  assert.equal(result?.records.at(-1)?.type, 5462);
  assert.deepEqual(issues, []);
});

void test("FIXUP preserves whole records before a short read without reading further", async () => {
  const subject = createExtraDebugPayloadSubject(payload());
  const issues: string[] = [];
  const reader = { size: subject.file.size, readBytes: subject.file.readBytes.bind(subject.file),
    read: (offset: number) => subject.file.read(offset, 12) };
  const result = await parseFixupInfo(reader, reader.size, identityRvaToOff, 0, subject.offset,
    subject.declaredSize, issue => issues.push(issue));

  assert.equal(result?.records.length, 1);
  assert.match(issues.join(" | "), /truncated/);
});

void test("FIXUP rejects unmapped payloads and supports RVA-only storage", async () => {
  const subject = createExtraDebugPayloadSubject(payload());
  const issues: string[] = [];
  const missing = await parseFixupInfo(subject.file, subject.file.size, () => null, 0, 0, 12,
    issue => issues.push(issue));
  const mapped = await parseFixupInfo(subject.file, subject.file.size, identityRvaToOff,
    subject.offset, 0, subject.declaredSize, issue => issues.push(issue));

  assert.equal(missing, null);
  assert.match(issues.join(" | "), /FIXUP debug entry has no PointerToRawData/);
  assert.equal(mapped?.records.length, 2);
});
