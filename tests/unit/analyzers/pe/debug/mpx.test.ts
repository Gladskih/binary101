import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMpxInfo } from "../../../../../analyzers/pe/debug/mpx.js";
import { createMpxPayload } from "../../../../fixtures/pe-debug-optimization.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../../../../fixtures/pe-debug-extra-payloads.js";

void test("MPX decodes the public JRBP layout and preserves unnamed fields", async () => {
  const expected = { flags: 5, unknown1: 3, unknown2: 17, unknown3: 0x12345678 };
  const { file, offset, declaredSize } = createExtraDebugPayloadSubject(createMpxPayload(expected));
  assert.deepEqual(await parseMpxInfo(file, file.size, identityRvaToOff, 0, offset,
    declaredSize, assert.fail), expected);
  assert.deepEqual(await parseMpxInfo(file, file.size, identityRvaToOff, offset, 0,
    declaredSize, assert.fail), expected);
});

void test("MPX rejects truncated headers and unrecognized signatures", async () => {
  const warnings: string[] = [];
  const { file, offset } = createExtraDebugPayloadSubject(createMpxPayload());
  assert.equal(await parseMpxInfo(file, file.size, identityRvaToOff, 0, offset, 19,
    message => warnings.push(message)), null);
  const bad = createMpxPayload();
  bad[0] = 0;
  const subject = createExtraDebugPayloadSubject(bad);
  assert.equal(await parseMpxInfo(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, bad.length, message => warnings.push(message)), null);
  assert.match(warnings.join(" | "), /smaller than.*20/);
  assert.match(warnings.join(" | "), /signature/);
});

void test("MPX reports unknown flag bits and uninterpreted extensions", async () => {
  const warnings: string[] = [];
  const payload = Uint8Array.from([...createMpxPayload({ flags: 0x80000007,
    unknown1: 0, unknown2: 0, unknown3: 0 }), 1]);
  const { file, offset } = createExtraDebugPayloadSubject(payload);
  const result = await parseMpxInfo(file, file.size, identityRvaToOff, 0, offset,
    payload.length, message => warnings.push(message));
  assert.equal(result?.flags, 0x80000007);
  assert.match(warnings.join(" | "), /unknown flag bits.*80000000/);
  assert.match(warnings.join(" | "), /trailing bytes/);
});

void test("MPX bounds errors and read failures become warnings", async () => {
  const warnings: string[] = [];
  const { file, offset } = createExtraDebugPayloadSubject(createMpxPayload());
  assert.equal(await parseMpxInfo(file, file.size, identityRvaToOff, 0, file.size, 20,
    message => warnings.push(message)), null);
  assert.equal(await parseMpxInfo(file, file.size, identityRvaToOff, 0, offset, -1,
    message => warnings.push(message)), null);
  assert.equal(await parseMpxInfo(file, file.size, identityRvaToOff, 0, 0, 20,
    message => warnings.push(message)), null);
  assert.equal(await parseMpxInfo({ size: file.size, readBytes: file.readBytes.bind(file),
    read: async () => new DataView(new ArrayBuffer(0)) },
    file.size, identityRvaToOff, 0, offset, 20, message => warnings.push(message)), null);
  assert.equal(await parseMpxInfo({ size: file.size, readBytes: file.readBytes.bind(file),
    read: async () => { throw new Error("I/O"); } },
    file.size, identityRvaToOff, 0, offset, 20, message => warnings.push(message)), null);
  assert.match(warnings.join(" | "), /past end/);
  assert.match(warnings.join(" | "), /truncated/);
  assert.match(warnings.join(" | "), /I\/O/);
});

void test("MPX checks physical truncation and extreme declared sizes", async () => {
  const warnings: string[] = [];
  const { file, offset } = createExtraDebugPayloadSubject(createMpxPayload().slice(0, 19));
  assert.equal(await parseMpxInfo(file, file.size, identityRvaToOff, 0, offset, 20,
    message => warnings.push(message)), null);
  assert.equal(await parseMpxInfo(file, file.size, identityRvaToOff, 0, offset, Infinity,
    message => warnings.push(message)), null);
  assert.match(warnings.join(" | "), /shorter than.*SizeOfData/);
  assert.match(warnings.join(" | "), /truncated/);
});

void test("MPX respects the supplied file boundary even if a reader could return more bytes", async () => {
  const warnings: string[] = [];
  const { file, offset, declaredSize } = createExtraDebugPayloadSubject(createMpxPayload());
  assert.equal(await parseMpxInfo(file, file.size - 1, identityRvaToOff, 0, offset,
    declaredSize, message => warnings.push(message)), null);
  assert.match(warnings.join(" | "), /truncated/);
});

void test("MPX identifies its unavailable data in diagnostics", async () => {
  const warnings: string[] = [];
  const { file, declaredSize } = createExtraDebugPayloadSubject(createMpxPayload());
  assert.equal(await parseMpxInfo(file, file.size, identityRvaToOff, 0, 0,
    declaredSize, message => warnings.push(message)), null);
  assert.match(warnings[0]!, /^MPX debug entry has no PointerToRawData/);
});
