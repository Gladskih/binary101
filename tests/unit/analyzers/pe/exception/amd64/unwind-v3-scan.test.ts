import assert from "node:assert/strict";
import { test } from "node:test";
import { scanAmd64UnwindInfos } from "../../../../../../analyzers/pe/exception/amd64/unwind-info.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import { createV3Unwind } from "../../../../../fixtures/pe-unwind-v3.js";

for (const [flags, handlerCount, chainedCount, version1Count, payloadBytes] of [
  [1, 1, 0, 0, [0, 4]], [4, 0, 1, 1, [0, 4]], [8, 0, 0, 0, [0, 0, 0, 4]]
] as const) {
  void test(`AMD64 scan decodes V3 payloads and preserves trailing metadata with flags ${flags}`, async () => {
    const bytes = new Uint8Array(64);
    const view = new DataView(bytes.buffer);
    const payload = createV3Unwind(payloadBytes, 1, flags, 1);
    bytes.set(new Uint8Array(payload.buffer), 8);
    view.setUint32(16, 40, true);
    view.setUint32(24, 32, true);
    bytes[32] = 1;
    const issues: string[] = [];
    const parsed = await scanAmd64UnwindInfos(new MockFile(bytes), rva => rva, new Set([8]), issues);

    assert.equal(parsed.version3?.blockCount, 1);
    assert.deepEqual(parsed.version3?.operationCounts, { PUSH: 1 });
    assert.equal(parsed.handlerUnwindInfoCount, handlerCount);
    assert.equal(parsed.chainedUnwindInfoCount, chainedCount);
    assert.equal(parsed.unwindInfoVersion1Count, version1Count);
    assert.deepEqual(issues, []);
  });
}

void test("AMD64 scan counts a V3 header while reporting its truncated payload", async () => {
  const bytes = new Uint8Array(12);
  bytes.set([3, 0, 10, 0], 8);
  const issues: string[] = [];
  const parsed = await scanAmd64UnwindInfos(new MockFile(bytes), rva => rva, new Set([8]), issues);

  assert.equal(parsed.version3?.blockCount, 1);
  assert.deepEqual(parsed.version3?.operationCounts, {});
  assert.deepEqual(issues, ["UNWIND_INFO v3 payload is shorter than PayloadWords declares."]);
});

void test("PE debug dispatch retains V3 statistics and deduplicates a shared unwind block", async () => {
  const { createPeWithV3ExceptionCopy } = await import("../../../../../fixtures/pe-debug-file.js");
  const { parsePeHeaders } = await import("../../../../../../analyzers/pe/core/index.js");
  const { parseDebugDirectory } = await import("../../../../../../analyzers/pe/debug/directory.js");
  const file = createPeWithV3ExceptionCopy();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const parsed = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);

  assert.equal(parsed.entries[0]?.exception?.functionCount, 2);
  assert.equal(parsed.entries[0]?.exception?.unwindInfoV3?.blockCount, 1);
  assert.deepEqual(parsed.entries[0]?.exception?.unwindInfoV3?.operationCounts, { PUSH: 1 });
  assert.deepEqual(parsed.entries[0]?.exception?.unwindInfoV3?.registerCounts, { R16: 1 });
  assert.deepEqual(parsed.entries[0]?.exception?.issues, []);
});

void test("AMD64 scan accumulates distinct V3 blocks without resetting their inventories", async () => {
  const bytes = new Uint8Array(32);
  bytes.set(new Uint8Array(createV3Unwind([0, 4], 1, 0, 1).buffer), 8);
  bytes.set(new Uint8Array(createV3Unwind([0, 12], 1, 0, 1).buffer), 16);
  const issues: string[] = [];
  const parsed = await scanAmd64UnwindInfos(new MockFile(bytes), rva => rva, new Set([8, 16]), issues);

  assert.equal(parsed.version3?.blockCount, 2);
  assert.deepEqual(parsed.version3?.operationCounts, { PUSH: 2 });
  assert.deepEqual(parsed.version3?.registerCounts, { RAX: 1, RCX: 1 });
  assert.deepEqual(parsed.version3?.prologSizeCounts, { 1: 2 });
  assert.deepEqual(issues, []);
});
