import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExceptionDirectory } from "../../../../../analyzers/pe/exception/index.js";
import { createArm64LinkChain } from "../../../../fixtures/pe-arm64-links.js";

for (const links of [12, 512]) {
  void test(`ARM64 resolves ${links} parent links using structural bounds instead of a fixed depth cap`, async context => {
    const { file, directory, code } = createArm64LinkChain(links);
    const read = context.mock.method(file, "read");
    const parsed = await parseExceptionDirectory(file, [directory], rva => rva, 0xaa64);

    assert.equal(parsed?.functionCount, links + 1);
    assert.equal(parsed?.chainedUnwindInfoCount, links);
    assert.equal(parsed?.invalidEntryCount, 0);
    assert.equal(parsed?.beginRvas[0], code);
    assert.deepEqual(parsed?.rangeLengths, [4]);
    assert.deepEqual(parsed?.issues, []);
    assert.equal(read.mock.calls.filter(call => call.arguments[1] === 8).length, links);
  });
}
