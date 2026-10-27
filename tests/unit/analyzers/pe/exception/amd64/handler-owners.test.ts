import assert from "node:assert/strict";
import { test } from "node:test";
import { readAmd64ChainedFunction, resolveAmd64HandlerOwners }
  from "../../../../../../analyzers/pe/exception/amd64/handler-owners.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

void test("handler ownership follows multi-level CHAININFO and merges shared terminal owners", () => {
  const direct = new Map([[0x2000, [{ begin: 0x1000, end: 0x1010 }]],
    [0x2010, [{ begin: 0x1100, end: 0x1110 }]], [0x2030, [{ begin: 0x1200, end: 0x1210 }]]]);
  const issues: string[] = [];
  const owners = resolveAmd64HandlerOwners(direct, new Map([[0x2000, 0x2010], [0x2010, 0x2030]]), issues);
  assert.deepEqual(owners.get(0x2030), [{ begin: 0x1000, end: 0x1010 },
    { begin: 0x1100, end: 0x1110 }, { begin: 0x1200, end: 0x1210 }]);
  assert.equal(owners.has(0x2000), false);
  assert.deepEqual(issues, []);
});

void test("CHAININFO validates the complete embedded runtime function row", async () => {
  const bytes = new Uint8Array(12);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x1000, true);
  view.setUint32(4, 0x1020, true);
  view.setUint32(8, 0x2000, true);
  const issues: string[] = [];
  assert.deepEqual(await readAmd64ChainedFunction(new MockFile(bytes), 0, issues,
    (begin, end) => begin === 0x1000 && end === 0x1020), { rva: 0x2000, validRange: true });
  assert.deepEqual(issues, []);
});

void test("CHAININFO reports truncation and an invalid range instead of using them as handler evidence", async () => {
  const issues: string[] = [];
  assert.equal(await readAmd64ChainedFunction(new MockFile(new Uint8Array(11)), 0, issues, () => true), null);
  assert.deepEqual(await readAmd64ChainedFunction(new MockFile(new Uint8Array(12)), 0, issues, () => false),
    { rva: 0, validRange: false });
  assert.match(issues[0] ?? "", /truncated/);
  assert.match(issues[1] ?? "", /invalid chained function range/);
});

void test("cyclic CHAININFO does not manufacture terminal handler owners", () => {
  const issues: string[] = [];
  const result = resolveAmd64HandlerOwners(new Map([[8, [{ begin: 0x1000, end: 0x1010 }]]]),
    new Map([[8, 16], [16, 8]]), issues);
  assert.equal(result.size, 0);
  assert.match(issues[0] ?? "", /CHAININFO.*cycle/);
});
