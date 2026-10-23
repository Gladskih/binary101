import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSpgoInfo } from "../../../../../analyzers/pe/debug/spgo.js";
import { createSpgoPayload } from "../../../../fixtures/pe-debug-optimization.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../../../../fixtures/pe-debug-extra-payloads.js";

void test("SPGO type 18 retains Unicode text, an initial BOM and supplementary characters", async () => {
  const text = "\ufeff<профиль>😀";
  const { file, offset, declaredSize } = createExtraDebugPayloadSubject(createSpgoPayload(text));
  assert.deepEqual(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, offset,
    declaredSize, assert.fail), { text });
  assert.deepEqual(await parseSpgoInfo(file, file.size, identityRvaToOff, offset, 0,
    declaredSize, assert.fail), { text });
});

void test("SPGO preserves empty strings and text spanning multiple bounded reads", async () => {
  const empty = createExtraDebugPayloadSubject(createSpgoPayload(""));
  assert.deepEqual(await parseSpgoInfo(empty.file, empty.file.size, identityRvaToOff,
    0, empty.offset, empty.declaredSize, assert.fail), { text: "" });
  const text = "x".repeat(255) + "😀" + "y".repeat(300);
  const { file, offset, declaredSize } = createExtraDebugPayloadSubject(createSpgoPayload(text));
  assert.deepEqual(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, offset,
    declaredSize, assert.fail), { text });
});

void test("SPGO reports trailing bytes without dropping the useful text", async () => {
  const warnings: string[] = [];
  const payload = Uint8Array.from([...createSpgoPayload("abc"), 1]);
  const { file, offset } = createExtraDebugPayloadSubject(payload);
  assert.deepEqual(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, offset,
    payload.length, message => warnings.push(message)), { text: "abc" });
  assert.match(warnings.join(" | "), /1 trailing byte/);
});

void test("SPGO rejects unterminated, odd-length and invalid UTF-16 strings", async () => {
  const warnings: string[] = [];
  const { file, offset, declaredSize } = createExtraDebugPayloadSubject(createSpgoPayload("abc"));
  assert.equal(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, offset,
    declaredSize - 2, message => warnings.push(message)), null);
  assert.equal(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, offset,
    declaredSize - 1, message => warnings.push(message)), null);
  const invalid = createExtraDebugPayloadSubject(createSpgoPayload("\ud800"));
  assert.equal(await parseSpgoInfo(invalid.file, invalid.file.size, identityRvaToOff,
    0, invalid.offset, invalid.declaredSize, message => warnings.push(message)), null);
  assert.match(warnings.join(" | "), /terminat/);
  assert.match(warnings.join(" | "), /UTF-16/);
});

void test("SPGO handles invalid locations, sizes and short or failing reads", async () => {
  const warnings: string[] = [];
  const { file, offset, declaredSize } = createExtraDebugPayloadSubject(createSpgoPayload());
  assert.equal(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, 0, declaredSize,
    message => warnings.push(message)), null);
  assert.equal(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, file.size, declaredSize,
    message => warnings.push(message)), null);
  assert.equal(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, offset, -1,
    message => warnings.push(message)), null);
  assert.equal(await parseSpgoInfo({ size: file.size, readBytes: file.readBytes.bind(file),
    read: async () => new DataView(new ArrayBuffer(0)) },
    file.size, identityRvaToOff, 0, offset, declaredSize, message => warnings.push(message)), null);
  assert.equal(await parseSpgoInfo({ size: file.size, readBytes: file.readBytes.bind(file),
    read: async () => { throw new Error("I/O"); } },
    file.size, identityRvaToOff, 0, offset, declaredSize, message => warnings.push(message)), null);
  assert.match(warnings.join(" | "), /truncated/);
  assert.match(warnings.join(" | "), /I\/O/);
});

void test("SPGO reports physical truncation and invalid sizes without inventing a terminator", async () => {
  const warnings: string[] = [];
  const payload = createSpgoPayload("abc");
  const { file, offset } = createExtraDebugPayloadSubject(payload.slice(0, -2));
  assert.equal(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, offset,
    payload.length, message => warnings.push(message)), null);
  assert.equal(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, offset, NaN,
    message => warnings.push(message)), null);
  assert.equal(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, offset, 0,
    message => warnings.push(message)), null);
  assert.match(warnings.join(" | "), /shorter than.*SizeOfData/);
  assert.match(warnings.join(" | "), /unterminated/);
});

void test("SPGO identifies its unavailable data and invalid sizes in diagnostics", async () => {
  const warnings: string[] = [];
  const { file, offset, declaredSize } = createExtraDebugPayloadSubject(createSpgoPayload());
  assert.equal(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, 0,
    declaredSize, message => warnings.push(message)), null);
  assert.match(warnings[0]!, /^SPGO debug entry has no PointerToRawData/);
  warnings.length = 0;
  assert.equal(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, offset,
    NaN, message => warnings.push(message)), null);
  assert.deepEqual(warnings, ["SPGO debug entry has an invalid size for a UTF-16 string."]);
});

void test("SPGO requires a terminator within its declared boundary", async () => {
  const warnings: string[] = [];
  const { file, offset, declaredSize } = createExtraDebugPayloadSubject(createSpgoPayload("abc"));
  assert.equal(await parseSpgoInfo(file, file.size, identityRvaToOff, 0, offset,
    declaredSize - 2, message => warnings.push(message)), null);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /unterminated or odd-length UTF-16/);
});
