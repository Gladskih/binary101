import assert from "node:assert/strict";
import { test } from "node:test";
import { readArm64XdataCodes } from "../../../../../analyzers/pe/exception/arm64-xdata-codes.js";
import { MockFile } from "../../../../helpers/mock-file.js";

void test("ARM64 xdata validates scope fields while preserving independently decodable operations", async () => {
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  // Two scope words: first starts past a 64-byte function and sets a reserved bit;
  // second goes backwards and enters the middle of an ALLOC_L operand.
  view.setUint32(8, 20 | (1 << 18) | (4 << 22), true);
  view.setUint32(12, 1 | (1 << 22), true);
  bytes.set([0xe0, 0, 0, 1, 0xe4], 16);
  const issues: string[] = [];
  const result = await readArm64XdataCodes(new MockFile(bytes), rva => rva,
    { codeRva: 16, codeSize: 8, scopeRva: 8, scopeCount: 2, epilogIndex: null }, 64, issues);

  assert.equal(result.hasDecodeGaps, true);
  assert.deepEqual(result.operations.map(value => value.opcode), ["alloc_l", "end"]);
  assert.match(issues.join(" "), /reserved bits/);
  assert.match(issues.join(" "), /outside its function/);
  assert.match(issues.join(" "), /not ordered/);
  assert.match(issues.join(" "), /inside an operand/);
});

void test("ARM64 code and scope reads retain bounded prefixes after physically short reads", async () => {
  const bytes = Uint8Array.from([0, 0, 0, 0, 0xe4]);
  const issues: string[] = [];
  const result = await readArm64XdataCodes(new MockFile(bytes), rva => rva,
    { codeRva: 4, codeSize: 4, scopeRva: 0, scopeCount: 2, epilogIndex: 9 }, 4, issues);

  assert.equal(result.hasDecodeGaps, true);
  assert.equal(result.operations[0]?.opcode, "end");
  assert.match(issues.join(" "), /scope array is truncated/);
  assert.match(issues.join(" "), /code pool is truncated/);
  assert.match(issues.join(" "), /index 9 is outside/);
});

void test("ARM64 shared epilog indices decode a valid pool once and ignore preceding diagnostics", async () => {
  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 1, true);
  bytes.set([0xe3, 0xe4, 255, 255], 8);
  const issues: string[] = ["Earlier record warning"];
  const result = await readArm64XdataCodes(new MockFile(bytes), rva => rva,
    { codeRva: 8, codeSize: 4, scopeRva: 0, scopeCount: 1, epilogIndex: 1 }, 8, issues);

  assert.equal(result.hasDecodeGaps, false);
  assert.deepEqual(result.operations.map(value => value.opcode), ["nop", "end"]);
  assert.deepEqual(issues, ["Earlier record warning"]);
});
