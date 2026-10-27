import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { createEhFixture, addFh3, addFh4, buildEhPeImage } from "../../../../fixtures/pe-msvc-eh.js";

for (const [build, version] of [[addFh3, 3], [addFh4, 4]] as const) {
  void test(`full PE parser exposes validated FH${version} with real import and unwind linkage`, async () => {
    const subject = createEhFixture();
    const { infoRva } = build(subject);
    const parsed = await parsePe(buildEhPeImage(subject));
    assert.ok(parsed && isPeWindowsParseResult(parsed));
    assert.equal(parsed.msvcEh?.records[0]?.functionInfo?.rva, infoRva);
    assert.equal(parsed.msvcEh?.records[0]?.functionInfo?.version, version);
    assert.deepEqual(parsed.msvcEh?.warnings, []);
  });
}
