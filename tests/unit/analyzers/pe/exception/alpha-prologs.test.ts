import assert from "node:assert/strict";
import { test } from "node:test";
import { recordAlphaProlog, finishAlphaPrologs } from "../../../../../analyzers/pe/exception/alpha-prologs.js";

void test("Alpha secondary ranges reference the primary procedure's begin VA in either directory order", () => {
  const state = { primaryBegins: new Set<bigint>(), secondaryBegins: [] as bigint[] };
  assert.equal(recordAlphaProlog(state, 0x2000n, 0x2040n, 0x1000n), null);
  assert.equal(recordAlphaProlog(state, 0x1000n, 0x1040n, 0x1010n), 0x1010n);
  assert.equal(recordAlphaProlog(state, 0x3000n, 0x3040n, 0x1000n), null);
  assert.deepEqual(finishAlphaPrologs(state), { resolvedSecondaryRanges: 2, unresolvedSecondaryRanges: 0 });
});

void test("Alpha primary boundary addresses remain direct and missing or cyclic references stay unresolved", () => {
  const state = { primaryBegins: new Set<bigint>(), secondaryBegins: [] as bigint[] };
  assert.equal(recordAlphaProlog(state, 0x1000n, 0x1040n, 0x1000n), 0x1000n);
  assert.equal(recordAlphaProlog(state, 0x2000n, 0x2040n, 0x2040n), 0x2040n);
  assert.equal(recordAlphaProlog(state, 0x3000n, 0x3040n, 0x4000n), null);
  assert.equal(recordAlphaProlog(state, 0x4000n, 0x4040n, 0x3000n), null);
  assert.deepEqual(finishAlphaPrologs(state), { resolvedSecondaryRanges: 0, unresolvedSecondaryRanges: 2 });
  assert.deepEqual(finishAlphaPrologs({ primaryBegins: new Set(), secondaryBegins: [] }),
    { resolvedSecondaryRanges: 0, unresolvedSecondaryRanges: 0 });
});
