import assert from "node:assert/strict";
import { test } from "node:test";
import { buildLegacyCodeViewDiscardedStatistics } from "../../../../renderers/pe/legacy-codeview-discarded-statistics.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";

void test("CodeView discarded statistics group actual reasons and summarize recorded source lines", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x125, module: 3, offset: 0, size: 0,
    data: { kind: "symbols", records: [
      { type: 0x113b, discarded: { reason: 2, fileId: 0xffffffff, line: 999 } },
      { type: 0x113b, discarded: { reason: 2, fileId: 0, line: 20 } },
      { type: 0x113b, discarded: { reason: 2, fileId: 1, line: 10 } },
      { type: 0xe, children: [{ type: 0x113b, discarded: { reason: 1, fileId: 0, line: 0 } }] },
      { type: 0x113b, discarded: { reason: 0, fileId: 0xffffffff, line: 0 } },
      { type: 0x113b, discarded: { reason: 17, fileId: 0xffffffff, line: 0 } }
    ] } });

  assert.deepEqual(buildLegacyCodeViewDiscardedStatistics(info), [{ key: "discardedSymbols",
    title: "Discarded records by reason", columns: ["Directory", "Module", "Reason", "Records",
      "With source line", "First source line", "Last source line"], rows: [
      ["1", "3", "Not referenced", "3", "2", "10", "20"],
      ["1", "3", "Not selected", "1", "1", "0", "0"],
      ["1", "3", "Unknown", "1", "0", "—", "—"], ["1", "3", "Unknown (17)", "1", "0", "—", "—"]
    ] }]);
});

void test("CodeView discarded statistics omit absent metadata and keep directory generations separate", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x125, module: 3, offset: 0, size: 0 });
  info.directories[0]!.subsections.push({ type: 0x125, module: 3, offset: 0, size: 0,
    data: { kind: "symbols", records: [{ type: 0x113b }] } });

  assert.deepEqual(buildLegacyCodeViewDiscardedStatistics(info), []);
  info.directories.push({ flags: 0, subsections: [{ type: 0x125, module: 4, offset: 0, size: 0,
    data: { kind: "symbols", records: [{ type: 0x113b, discarded: { reason: 1, fileId: 0xffffffff, line: 0 } }] } }] });
  assert.deepEqual(buildLegacyCodeViewDiscardedStatistics(info)[0]!.rows,
    [["2", "4", "Not selected", "1", "0", "—", "—"]]);
});
