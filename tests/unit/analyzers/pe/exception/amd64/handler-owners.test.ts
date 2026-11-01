import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeAmd64ChainedFunction, readAmd64ChainedFunction, resolveAmd64HandlerOwners }
  from "../../../../../../analyzers/pe/exception/amd64/handler-owners.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

void test("unmerged ranges are reused and merging preserves the direct inventory", context => {
  const unrelated = [{ begin: 0x1000, end: 0x1010 }];
  const child = [{ begin: 0x1100, end: 0x1110 }];
  const terminal = [{ begin: 0x1200, end: 0x1210 }];
  const last = [{ begin: 0x1300, end: 0x1310 }];
  const direct = new Map([[4, unrelated], [8, child], [12, terminal], [16, last]]);
  const issues: string[] = [];
  const sets = context.mock.method(globalThis, "Set");
  const slice = Array.prototype.slice;
  let copiedArrays = 0;
  Array.prototype.slice = function(this: unknown[], start?: number, end?: number) {
    copiedArrays++;
    return slice.call(this, start, end) as unknown[];
  };
  context.after(() => { Array.prototype.slice = slice; });
  const initialSets = sets.mock.callCount();

  const owners = resolveAmd64HandlerOwners(direct, new Map([[8, 12], [16, 12]]), issues);
  const allocatedSets = sets.mock.callCount() - initialSets;
  Array.prototype.slice = slice;
  sets.mock.restore();

  // Only the two actual chain walks and one shared merge tracker need sets.
  assert.ok(allocatedSets <= 3, `${allocatedSets} sets allocated for two chain walks`);
  assert.ok(copiedArrays <= 1, `${copiedArrays} copies allocated for one merged owner`);
  assert.strictEqual(owners.get(4), unrelated);
  assert.deepEqual(owners.get(12), [...child, ...terminal, ...last]);
  assert.deepEqual(direct, new Map([[4, unrelated], [8, child], [12, terminal], [16, last]]));
  assert.equal(child.length, 1);
  assert.equal(terminal.length, 1);
  assert.equal(last.length, 1);
  assert.deepEqual(issues, []);
});

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

void test("shared cyclic CHAININFO suffixes produce one diagnostic", () => {
  const issues: string[] = [];
  const direct = new Map([[8, [{ begin: 0x1000, end: 0x1010 }]],
    [16, [{ begin: 0x1100, end: 0x1110 }]]]);

  const owners = resolveAmd64HandlerOwners(direct, new Map([[8, 16], [16, 8]]), issues);

  assert.equal(owners.size, 0);
  assert.deepEqual(issues,
    ["UNWIND_INFO CHAININFO contains a cycle; handler ownership is unresolved."]);
});

void test("in-memory CHAININFO decoding honors the view's physical offset", () => {
  const view = new DataView(new ArrayBuffer(20), 4, 12);
  view.setUint32(0, 0x1230, true);
  view.setUint32(4, 0x1240, true);
  view.setUint32(8, 0x5670, true);
  const issues: string[] = [];
  assert.deepEqual(decodeAmd64ChainedFunction(view, issues,
    (begin, end) => begin === 0x1230 && end === 0x1240), { rva: 0x5670, validRange: true });
  assert.deepEqual(issues, []);
});
