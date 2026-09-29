import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRibbonBmlTree } from "../../../../../../analyzers/pe/resources/preview/ribbon-bml-tree.js";

const ribbonTree = (): Uint8Array => Uint8Array.from([
  // new.ksy: node(22), array(24), node(22), numeric ID property(1).
  22, 0, 36, 0, 16, 0, 0, 1,
  24, 1, 0, 1, 0,
  22, 0, 15, 0, 16, 0, 0, 1,
  1, 1, 0, 3, 0x34, 0x12
]);

void test("parses nested Ribbon controls and command IDs", () => {
  const issues: string[] = [];
  assert.deepEqual(parseRibbonBmlTree(ribbonTree(), 0, issues), {
    kind: "Type 36", commandId: null, children: [
      { kind: "Button", commandId: 0x1234, children: [] }
    ]
  });
  assert.deepEqual(issues, []);
});

void test("skips command containers and extension references before the root", () => {
  const bytes = Uint8Array.from([16, 9, 0, 0, 0, 0, 0, 0, 0,
    13, 3, 0, 0, 0, 0, 0, ...ribbonTree()]);
  const issues: string[] = [];
  assert.equal(parseRibbonBmlTree(bytes, 0, issues)?.children[0]?.kind, "Button");
  assert.deepEqual(issues, []);
});

void test("reports unknown entries and every truncated prefix", () => {
  const fixture = ribbonTree();
  const unknown: string[] = [];
  assert.equal(parseRibbonBmlTree(Uint8Array.of(99), 0, unknown), null);
  assert.match(unknown.join(" "), /unknown/);
  for (let length = 0; length < fixture.length; length += 1) {
    const issues: string[] = [];
    assert.doesNotThrow(() => parseRibbonBmlTree(fixture.subarray(0, length), 0, issues));
  }
});

void test("skips documented size and long-property entries", () => {
  const skip = [59, 9, 0, 59, 3, 0, 0, 59, 2, 0, 0, 0, 0,
    1, 4, 68, 0, 0, 0, 0, 0];
  const issues: string[] = [];
  assert.equal(parseRibbonBmlTree(Uint8Array.from([...skip, ...ribbonTree()]),
    0, issues)?.kind, "Type 36");
  assert.deepEqual(issues, []);
});

void test("follows an extension reference to its control block", () => {
  // new.ksy type_tree_entry_ext: absolute position, u16 block size, then an entry.
  const bytes = Uint8Array.from([
    22, 0, 36, 0, 16, 0, 0, 1,
    62, 13, 0, 0, 0,
    10, 0, 22, 0, 15, 0, 16, 0, 0, 0
  ]);
  const issues: string[] = [];
  assert.deepEqual(parseRibbonBmlTree(bytes, 0, issues)?.children,
    [{ kind: "Button", commandId: null, children: [] }]);
  assert.deepEqual(issues, []);
});

void test("rejects invalid, cyclic and oversized extension targets", () => {
  const invalid: string[] = [];
  assert.equal(parseRibbonBmlTree(Uint8Array.from([62, 99, 0, 0, 0]),
    0, invalid), null);
  assert.match(invalid.join(" "), /extension target/);
  const cyclic: string[] = [];
  assert.equal(parseRibbonBmlTree(Uint8Array.from([62, 5, 0, 0, 0,
    7, 0, 62, 5, 0, 0, 0]), 0, cyclic), null);
  assert.match(cyclic.join(" "), /cyclic/);
  const oversized: string[] = [];
  assert.equal(parseRibbonBmlTree(Uint8Array.from([62, 5, 0, 0, 0,
    3, 0, 22, 0, 15, 0, 16, 0, 0, 0]), 0, oversized), null);
  assert.match(oversized.join(" "), /declared size/);
  const outOfFile: string[] = [];
  assert.equal(parseRibbonBmlTree(Uint8Array.from([62, 5, 0, 0, 0,
    0xff, 0xff, 22, 0, 15, 0, 16, 0, 0, 0]), 0, outOfFile), null);
  assert.deepEqual(outOfFile, ["Compiled BML control tree extension block size is invalid."]);
});

void test("resumes after extension references and permits repeated targets", () => {
  const bytes = Uint8Array.from([
    22, 0, 36, 0, 16, 0, 0, 1,
    24, 1, 0, 2, 0,
    62, 23, 0, 0, 0, 62, 23, 0, 0, 0,
    10, 0, 22, 0, 15, 0, 16, 0, 0, 0
  ]);
  // The second reference uses the same absolute position as the first.
  const issues: string[] = [];
  const tree = parseRibbonBmlTree(bytes, 0, issues);
  assert.deepEqual(tree?.children.map(child => child.kind), ["Button", "Button"]);
  assert.deepEqual(issues, []);
});

void test("decodes each documented command ID width", () => {
  // new.ksy type_id: flags 2/3/4/9/43 carry 4/2/1/1/1 bytes.
  const ids: Array<[number, number[], number]> = [
    [2, [0x78, 0x56, 0x34, 0x12], 0x12345678],
    [3, [0x34, 0x12], 0x1234],
    [4, [42], 42], [9, [42], 42], [43, [42], 42]
  ];
  for (const [flag, payload, expected] of ids) {
    const bytes = Uint8Array.from([22, 0, 15, 0, 16, 0, 0, 1,
      1, 1, 0, flag, ...payload]);
    const issues: string[] = [];
    assert.equal(parseRibbonBmlTree(bytes, 0, issues)?.commandId, expected);
    assert.deepEqual(issues, []);
  }
});

void test("reports invalid offsets and unsupported property encodings", () => {
  const issues: string[] = [];
  assert.equal(parseRibbonBmlTree(ribbonTree(), -1, issues), null);
  assert.match(issues.join(" "), /offset/);
  const invalidSize = Uint8Array.from([1, 2, 0, 0]);
  const sizeIssues: string[] = [];
  assert.equal(parseRibbonBmlTree(invalidSize, 0, sizeIssues), null);
  assert.match(sizeIssues.join(" "), /property size/);
  const invalidFlag = Uint8Array.from([1, 1, 0, 99]);
  const flagIssues: string[] = [];
  assert.equal(parseRibbonBmlTree(invalidFlag, 0, flagIssues), null);
  assert.match(flagIssues.join(" "), /ID encoding/);
});

void test("bounds checks command containers and recursive arrays", () => {
  const badContainer = Uint8Array.from([16, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]);
  const containerIssues: string[] = [];
  assert.equal(parseRibbonBmlTree(badContainer, 0, containerIssues), null);
  assert.match(containerIssues.join(" "), /container size/);
  const nested = Uint8Array.from([...Array.from({ length: 34 }, () =>
    [24, 1, 0, 1, 0]).flat(), ...ribbonTree()]);
  const depthIssues: string[] = [];
  assert.equal(parseRibbonBmlTree(nested, 0, depthIssues), null);
  assert.match(depthIssues.join(" "), /nesting limit/);
});

void test("recognizes documented Ribbon control types", () => {
  // UIRibbon-Reversing/new.ksy enum_type_control values.
  const types: Array<[number, string]> = [
    [4, "Context popup"], [5, "Mini toolbar"], [6, "Check box"], [7, "Group"],
    [13, "Spinner"], [15, "Button"], [18, "Split button"], [19, "Application menu"],
    [20, "Drop-down button"], [21, "Gallery"], [24, "Menu group"], [26, "Tab"],
    [27, "Tab group"], [37, "Quick access"], [38, "Subgroup"]
  ];
  for (const [code, expected] of types) {
    const issues: string[] = [];
    assert.equal(parseRibbonBmlTree(Uint8Array.from([22, 0, code, 0,
      16, 0, 0, 0]), 0, issues)?.kind, expected);
    assert.deepEqual(issues, []);
  }
});

void test("reports precise warnings for malformed control entries", () => {
  const cases: Array<[number[], string]> = [
    [[99], "Compiled BML control tree entry type is unknown."],
    [[1], "Compiled BML control tree property is truncated."],
    [[1, 4, 0, 0], "Compiled BML control tree long property is truncated."],
    [[1, 2, 0, 0], "Compiled BML control tree property size is unsupported."],
    [[1, 1, 0, 99], "Compiled BML control tree property ID encoding is unsupported."],
    [[1, 1, 0, 3, 1], "Compiled BML control tree property ID is truncated."],
    [[22], "Compiled BML control tree node is truncated."],
    [[24], "Compiled BML control tree array is truncated."],
    [[13], "Compiled BML control tree command extension is truncated."],
    [[62], "Compiled BML control tree extension is truncated."],
    [[59], "Compiled BML control tree size entry is truncated."],
    [[59, 1], "Compiled BML control tree size entry flag is unsupported."],
    [[59, 2, 0], "Compiled BML control tree size entry is truncated."],
    [[16], "Compiled BML control tree command container is truncated."],
    [[16, 8, 0, 0, 0, 0, 0, 0, 0],
      "Compiled BML control tree command container size is invalid."],
    [[62, 5, 0, 0, 0, 2, 0], "Compiled BML control tree extension block size is invalid."]
  ];
  for (const [data, expected] of cases) {
    const issues: string[] = [];
    assert.equal(parseRibbonBmlTree(Uint8Array.from(data), 0, issues), null);
    assert.deepEqual(issues, [expected]);
  }
});

void test("retains a command ID when a later property has another kind", () => {
  const bytes = Uint8Array.from([22, 0, 15, 0, 16, 0, 0, 2,
    1, 1, 0, 4, 42, 1, 1, 7, 4, 99]);
  const issues: string[] = [];
  assert.equal(parseRibbonBmlTree(bytes, 0, issues)?.commandId, 42);
  assert.deepEqual(issues, []);
});

void test("keeps only command ID properties and preserves child order", () => {
  const bytes = Uint8Array.from([
    22, 0, 36, 0, 16, 0, 0, 2,
    1, 1, 7, 4, 99,
    24, 1, 0, 2, 0,
    22, 0, 15, 0, 16, 0, 0, 0,
    22, 0, 26, 0, 16, 0, 0, 0
  ]);
  const issues: string[] = [];
  const tree = parseRibbonBmlTree(bytes, 0, issues);
  assert.equal(tree?.commandId, null);
  assert.deepEqual(tree?.children.map(child => child.kind), ["Button", "Tab"]);
  assert.deepEqual(issues, []);
});

void test("rejects fractional and out-of-range tree offsets", () => {
  for (const offset of [0.5, -1, ribbonTree().length + 1]) {
    const issues: string[] = [];
    assert.equal(parseRibbonBmlTree(ribbonTree(), offset, issues), null);
    assert.deepEqual(issues, ["Compiled BML control tree offset is invalid."]);
  }
});
