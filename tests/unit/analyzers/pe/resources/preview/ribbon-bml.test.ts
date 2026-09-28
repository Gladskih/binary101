import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRibbonBml } from "../../../../../../analyzers/pe/resources/preview/ribbon-bml.js";

const fixture = (): Uint8Array => {
  // UIRibbon-Reversing/new.ksy: SCBin header, one string and one command resource.
  const strings = [1, 1, 1, 5, 0, 83, 109, 97, 108, 108, 15];
  const bytes = Uint8Array.from([0, 18, 0, 0, 0, 0, 0, 1, 0,
    83, 67, 66, 105, 110, 0, 0, 0, 0, 2, 0, 0, 0, 0,
    ...strings, 1, 0, 0, 0,
    100, 0, 0, 0, 2, 1, 200, 0, 0, 0, 5, 201, 0, 0, 0, 96, 0]);
  const view = new DataView(bytes.buffer);
  view.setUint32(14, bytes.length, true);
  view.setUint32(19, strings.length + 4, true);
  return bytes;
};

void test("parses compiled Ribbon strings and command resources", () => {
  const issues: string[] = [];
  assert.deepEqual(parseRibbonBml(fixture(), issues), { strings: ["Small"], commands: [
    { id: 100, resources: [{ kind: "Label title", resourceId: 200 },
      { kind: "Small image", resourceId: 201, minimumDpi: 96 }] }
  ] });
  assert.deepEqual(issues, []);
});

void test("bounds checks the header and declared string-section size", () => {
  const bytes = fixture();
  const truncated: string[] = [];
  assert.equal(parseRibbonBml(bytes.subarray(0, 22), truncated), null);
  assert.deepEqual(truncated, ["Compiled BML header is invalid or truncated."]);
  new DataView(bytes.buffer).setUint32(19, 0xffffffff, true);
  const invalid: string[] = [];
  assert.deepEqual(parseRibbonBml(bytes, invalid), { strings: [], commands: [] });
  assert.deepEqual(invalid, ["Compiled BML string-section length is invalid."]);
});

void test("reports header anomalies and preserves bounded table data", () => {
  const bytes = fixture();
  bytes[18] = 3;
  new DataView(bytes.buffer).setUint32(14, bytes.length + 1, true);
  const issues: string[] = [];
  assert.equal(parseRibbonBml(bytes, issues)?.commands[0]?.id, 100);
  assert.deepEqual(issues, ["Compiled BML declared length differs from resource size.",
    "Compiled BML string-section marker is unknown."]);
});

void test("reports malformed and truncated strings", () => {
  const bytes = fixture();
  bytes[23] = 0;
  const invalid: string[] = [];
  assert.deepEqual(parseRibbonBml(bytes, invalid)?.strings, []);
  assert.deepEqual(invalid, ["Compiled BML string table is invalid or truncated."]);
  bytes[23] = 1;
  bytes[25] = 0;
  const entry: string[] = [];
  assert.deepEqual(parseRibbonBml(bytes, entry)?.strings, []);
  assert.deepEqual(entry, ["Compiled BML string entry is invalid or truncated."]);
  bytes[25] = 1;
  bytes[26] = 0xff;
  const string: string[] = [];
  assert.deepEqual(parseRibbonBml(bytes, string)?.strings, []);
  assert.deepEqual(string, ["Compiled BML string is truncated."]);
});

void test("reports truncated command headers, resources and DPI fields", () => {
  const bytes = fixture();
  const header: string[] = [];
  assert.deepEqual(parseRibbonBml(bytes.subarray(0, 35), header)?.commands, []);
  assert.ok(header.includes("Compiled BML command table is truncated."));
  const command: string[] = [];
  assert.deepEqual(parseRibbonBml(bytes.subarray(0, 39), command)?.commands, []);
  assert.ok(command.includes("Compiled BML command record is truncated."));
  const resource: string[] = [];
  assert.deepEqual(parseRibbonBml(bytes.subarray(0, 44), resource)?.commands, []);
  assert.ok(resource.includes("Compiled BML command resource is truncated."));
  const dpi: string[] = [];
  assert.deepEqual(parseRibbonBml(bytes.subarray(0, bytes.length - 1), dpi)?.commands, []);
  assert.ok(dpi.includes("Compiled BML image DPI is truncated."));
});

void test("recognizes unknown resource kinds without throwing", () => {
  const bytes = fixture();
  bytes[43] = 77;
  const issues: string[] = [];
  assert.equal(parseRibbonBml(bytes, issues)?.commands[0]?.resources[0]?.kind, "Type 77");
  assert.deepEqual(issues, []);
});

void test("recognizes all documented resource kinds and image DPI variants", () => {
  const names = ["Label title", "Label description", "Small high contrast image",
    "Large high contrast image", "Small image", "Large image", "Key tip",
    "Tooltip title", "Tooltip description"];
  for (let type = 1; type <= 9; type += 1) {
    const bytes = fixture();
    bytes[42] = 1;
    bytes[43] = type;
    const result = parseRibbonBml(bytes, []);
    assert.equal(result?.commands[0]?.resources[0]?.kind, names[type - 1]);
    assert.equal(result?.commands[0]?.resources[0]?.resourceId, 200);
    assert.equal(result?.commands[0]?.resources[0]?.minimumDpi !== undefined,
      type >= 3 && type <= 6);
  }
});

void test("reads a resource after an image DPI field", () => {
  const bytes = fixture();
  const extended = Uint8Array.from([...bytes, 7, 202, 0, 0, 0]);
  const view = new DataView(extended.buffer);
  view.setUint32(14, extended.length, true);
  extended[42] = 3;
  const issues: string[] = [];
  assert.deepEqual(parseRibbonBml(extended, issues)?.commands[0]?.resources,
    [{ kind: "Label title", resourceId: 200 },
      { kind: "Small image", resourceId: 201, minimumDpi: 96 },
      { kind: "Key tip", resourceId: 202 }]);
  assert.deepEqual(issues, []);
});

void test("rejects every incorrect SCBin prefix byte", () => {
  for (let index = 0; index < 14; index += 1) {
    const bytes = fixture();
    bytes[index] = (bytes[index] ?? 0) ^ 0xff;
    const issues: string[] = [];
    assert.equal(parseRibbonBml(bytes, issues), null);
    assert.deepEqual(issues, ["Compiled BML header is invalid or truncated."]);
  }
});

void test("accepts a minimal empty string table and detects adjacent invalid sizes", () => {
  const bytes = Uint8Array.from([0, 18, 0, 0, 0, 0, 0, 1, 0,
    83, 67, 66, 105, 110, 30, 0, 0, 0, 2, 7, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0]);
  const issues: string[] = [];
  assert.deepEqual(parseRibbonBml(bytes, issues), { strings: [], commands: [] });
  assert.deepEqual(issues, []);
  new DataView(bytes.buffer).setUint32(19, 6, true);
  const invalid: string[] = [];
  assert.deepEqual(parseRibbonBml(bytes, invalid), { strings: [], commands: [] });
  assert.deepEqual(invalid, ["Compiled BML string-section length is invalid."]);
});

void test("reports string-table length and command-record errors exactly", () => {
  const bytes = fixture();
  bytes[24] = 0;
  const strings: string[] = [];
  assert.deepEqual(parseRibbonBml(bytes, strings)?.strings, []);
  assert.deepEqual(strings, ["Compiled BML string table size is inconsistent."]);
  bytes[24] = 1;
  // Count promises a second command, but the resource ends after the first.
  new DataView(bytes.buffer).setUint32(34, 2, true);
  const commands: string[] = [];
  assert.equal(parseRibbonBml(bytes, commands)?.commands.length, 1);
  assert.deepEqual(commands, ["Compiled BML command record is truncated."]);
});
