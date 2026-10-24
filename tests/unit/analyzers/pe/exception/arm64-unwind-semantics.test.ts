import assert from "node:assert/strict";
import { test } from "node:test";
import { createArm64UnwindInfoReader } from "../../../../../analyzers/pe/exception/arm64-unwind-info.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { createArm64UnwindSummaryPe } from "../../../../fixtures/pe-arm64-unwind-summary.js";
import { parsePeHeaders } from "../../../../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";

void test("ARM64 xdata decodes shared prolog/epilog operations without treating padding as instructions", async () => {
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  // Function length=64, E=1, epilog index=0, CodeWords=2.
  // alloc_s 32; save_fplr_x 32; set_fp; end; unused word padding.
  view.setUint32(8, 16 | (1 << 21) | (2 << 27), true);
  bytes.set([2, 0x83, 0xe1, 0xe4, 0, 0, 0, 0], 12);
  const issues: string[] = [];
  const info = await createArm64UnwindInfoReader(new MockFile(bytes), rva => rva)(8, issues);

  assert.equal(info?.unwind?.operations.length, 4);
  assert.deepEqual(info?.unwind?.operations.map(value => value.opcode), ["alloc_s", "save_fplr_x", "set_fp", "end"]);
  assert.equal(info?.unwind?.hasDecodeGaps, false);
  assert.deepEqual(issues, []);
});

void test("ARM64 debug copies expose shared code statistics alongside packed-frame summaries", async () => {
  const file = createArm64UnwindSummaryPe();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const parsed = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const exception = parsed.entries[0]?.exception;
  assert.ok(exception?.arm64Unwind);

  assert.equal(exception.functionCount, 2);
  assert.equal(exception.arm64Unwind.blockCount, 1);
  assert.equal(exception.arm64Unwind.operationCounts["save_next"], 1);
  assert.deepEqual(exception.arm64Packed?.frameSizeCounts, { 128: 1 });
  assert.deepEqual(exception.issues, []);
});
