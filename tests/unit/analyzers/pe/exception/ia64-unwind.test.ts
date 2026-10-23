import assert from "node:assert/strict";
import { test } from "node:test";
import { parseIa64UnwindInfo } from "../../../../../analyzers/pe/exception/ia64-unwind.js";
import { ia64ExceptionMap } from "../../../../fixtures/pe-ia64-exception.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const infoImage = (version = 3, flags = 3, length = 1): MockFile => {
  const bytes = new Uint8Array(512);
  const view = new DataView(bytes.buffer);
  view.setUint16(0x180, version, true);
  view.setUint16(0x182, flags, true);
  view.setUint32(0x184, length, true);
  bytes.set([3, 0xe0, 0, 3, 0x25, 0xc0, 0, 0], 0x188);
  return new MockFile(bytes);
};

void test("Windows IA64 v3 reads 16-bit version/flags and doubleword descriptor lengths", async () => {
  const parsed = await parseIa64UnwindInfo(infoImage(), ia64ExceptionMap, 0x1180);

  assert.equal(parsed.version, 3);
  assert.equal(parsed.flags, 3);
  assert.deepEqual(parsed.counts, { "Prologue regions": 1, "Fixed stack allocations": 1,
    "Body regions": 1, "Epilogues": 1, "Empty prologues / padding": 1 });
  assert.equal(parsed.maximumFixedStackBytes, 48);
  assert.deepEqual(parsed.issues, []);
});

void test("IA64 preserves unknown versions and flags without applying x64 or future layouts", async () => {
  const unknown = await parseIa64UnwindInfo(infoImage(1), ia64ExceptionMap, 0x1180);
  const flags = await parseIa64UnwindInfo(infoImage(3, 4), ia64ExceptionMap, 0x1180);

  assert.equal(unknown.version, 1);
  assert.equal(unknown.flags, 3);
  assert.deepEqual(unknown.counts, {});
  assert.match(unknown.issues[0]!, /version 1 is not decoded/);
  assert.equal(flags.flags, 4);
  assert.equal(flags.counts["Fixed stack allocations"], 1);
  assert.match(flags.issues[0]!, /unknown flag bits/);
});

void test("IA64 bounds the header and reports misalignment", async () => {
  const missing = await parseIa64UnwindInfo(infoImage(), ia64ExceptionMap, 0x11fc);
  const unaligned = await parseIa64UnwindInfo(infoImage(), rva => ia64ExceptionMap(rva - 1), 0x1181);
  const empty = await parseIa64UnwindInfo(infoImage(3, 0, 0), ia64ExceptionMap, 0x1180);

  assert.deepEqual(missing.counts, {});
  assert.equal(missing.version, undefined);
  assert.match(missing.issues[0]!, /header.*truncated/);
  assert.match(unaligned.issues[0]!, /not 8-byte aligned/);
  assert.equal(unaligned.counts["Fixed stack allocations"], 1);
  assert.deepEqual(empty.counts, {});
  assert.deepEqual(empty.issues, []);
});

void test("IA64 bounds extreme declared lengths while retaining available descriptors", async () => {
  const parsed = await parseIa64UnwindInfo(infoImage(3, 0, 0xffffffff), ia64ExceptionMap, 0x1180);

  assert.equal(parsed.counts["Fixed stack allocations"], 1);
  assert.match(parsed.issues[0]!, /descriptor area is truncated/);
});

void test("IA64 handles a short physical header read without throwing", async () => {
  const file = infoImage();
  const parsed = await parseIa64UnwindInfo({ size: file.size,
    read: async () => new DataView(new ArrayBuffer(4)), readBytes: (offset, size) => file.readBytes(offset, size)
  }, ia64ExceptionMap, 0x1180);

  assert.equal(parsed.version, undefined);
  assert.match(parsed.issues[0]!, /header.*truncated/);
});
