import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeCodeExclusions, createPeCodeExclusionIndex } from
  "../../../../../analyzers/pe/disassembly/code-exclusions.js";
import { peIsaDataOptions } from "../../../../fixtures/isa-known-data.js";
import { createPeFlowStopFixture } from "../../../../fixtures/pe-flow-stop.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { createPeImportNamesFile } from "../../../../fixtures/pe-import-names-file.js";

void test("PE exports mark only known starts without inventing object lengths", () => {
  const opts = peIsaDataOptions(0x8664);
  opts.dataRvas = [0x1008, -1, Number.NaN, 0x1_0000_0000, 0];

  assert.deepEqual(collectPeCodeExclusions(opts), [{ start: 0x401008n, end: 0x401009n }]);
  assert.equal(createPeCodeExclusionIndex(opts)(0x401009n, 1), null);
});

for (const bitness of [32, 64] as const) {
  void test(`PE${bitness} IAT byte widths and invalid slot addresses are bounded`, () => {
    const { options } = createPeFlowStopFixture(bitness, [0xc3]);
    const base = options.imageBase;
    const width = BigInt(bitness / 8);

    assert.deepEqual(collectPeCodeExclusions(options), [{ start: base + 0x2000n,
      end: base + 0x2000n + width }]);
    options.imports!.entries[0]!.firstThunkRva = 0xffff_fffe;
    assert.deepEqual(collectPeCodeExclusions(options), []);
    delete options.imports;
    assert.deepEqual(collectPeCodeExclusions(options), []);
  });
}

void test("delay-import address cells have the same exact byte protection as eager imports", async () => {
  const parsed = await parsePe(new File([createPeImportNamesFile()], "delayed.dll"));
  assert.ok(parsed && isPeWindowsParseResult(parsed) && parsed.delayImports);
  const opts = peIsaDataOptions(0x8664);
  opts.dataRvas = [];
  opts.delayImports = parsed.delayImports;
  const range = collectPeCodeExclusions(opts)[0]!;

  assert.equal(range.start, opts.imageBase + BigInt(parsed.delayImports.entries[0]!.ImportAddressTableRVA));
  assert.equal(range.end - range.start, 8n);
});
