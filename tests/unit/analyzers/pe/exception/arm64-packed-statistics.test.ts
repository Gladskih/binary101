import assert from "node:assert/strict";
import { test } from "node:test";
import { parseArm64ExceptionTable } from "../../../../../analyzers/pe/exception/arm64.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { createArm64PackedStatistics, recordArm64PackedStatistics }
  from "../../../../../analyzers/pe/exception/arm64-packed-statistics.js";

void test("ARM64 packed frame statistics count entries rather than unique packed words", async () => {
  const bytes = new Uint8Array(256);
  const view = new DataView(bytes.buffer);
  // Packed ARM64: length=4, RegF=1 saves D8/D9, RegI=2 saves X19/X20,
  // H=1 homes X0-X7, CR=2 signs LR and chains FP/LR, FrameSize=128.
  // https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#packed-unwind-data
  const word = 5 | (1 << 13) | (2 << 16) | (1 << 20) | (2 << 21) | (8 << 23);
  [128, word, 132, word].forEach((value, index) => view.setUint32(32 + index * 4, value, true));
  const parsed = await parseArm64ExceptionTable(new MockFile(bytes),
    new MockFile(bytes.subarray(32, 48)), 16, rva => rva, 32);

  assert.equal(parsed.uniqueUnwindInfoCount, 1);
  assert.deepEqual(parsed.arm64Packed?.frameSizeCounts, { 128: 2 });
  assert.deepEqual(parsed.arm64Packed?.registerCounts, { X19: 2, X20: 2, D8: 2, D9: 2, X29: 2, LR: 2 });
  assert.equal(parsed.arm64Packed?.homesParametersCount, 2);
  assert.deepEqual(parsed.arm64Packed?.returnKinds, { 2: 2 });
  assert.deepEqual(parsed.issues, []);
});

void test("ARM64 packed summaries preserve every return mode and the special RegF zero encoding", () => {
  const statistics = createArm64PackedStatistics();
  recordArm64PackedStatistics(statistics, 5); // No registers/frame storage.
  recordArm64PackedStatistics(statistics, 6 | (1 << 21) | (2 << 23)); // Fragment, LR only.
  recordArm64PackedStatistics(statistics, 5 | (3 << 21) | (7 << 13) | (10 << 16) | (511 << 23));
  recordArm64PackedStatistics(statistics, 0);
  recordArm64PackedStatistics(statistics, 3);

  assert.deepEqual(statistics.frameSizeCounts, { 0: 1, 32: 1, 8176: 1 });
  assert.deepEqual(statistics.returnKinds, { 0: 1, 1: 1, 3: 1 });
  assert.equal(statistics.fragmentCount, 1);
  assert.equal(statistics.homesParametersCount, 0);
  assert.deepEqual(statistics.registerCounts, { LR: 2, X29: 1,
    X19: 1, X20: 1, X21: 1, X22: 1, X23: 1, X24: 1, X25: 1, X26: 1, X27: 1, X28: 1,
    D8: 1, D9: 1, D10: 1, D11: 1, D12: 1, D13: 1, D14: 1, D15: 1 });
});

void test("ARM64 packed invalid register groups remain visible without fabricating X29-X33 saves", async () => {
  const bytes = new Uint8Array(64);
  const view = new DataView(bytes.buffer);
  view.setUint32(8, 32, true);
  view.setUint32(12, 5 | (15 << 16), true);
  const parsed = await parseArm64ExceptionTable(new MockFile(bytes),
    new MockFile(bytes.subarray(8, 16)), 8, rva => rva, 8);

  assert.deepEqual(parsed.arm64Packed?.registerCounts, {});
  assert.match(parsed.issues.join(" "), /RegI exceeds the X19-X28 register group/);
});
