"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDotNetResources } from "../../../../../analyzers/pe/clr/dotnet-resources.js";

import { makeDotNetResources, runtimeHeaderOffset, runtimeTableOffset, stringResourceValue }
  from "../../../../fixtures/dotnet-resource-file.js";

// ResourceManager has three 32-bit header fields.
const RESOURCE_MANAGER_FIXED_HEADER_SIZE = 12;
const RESOURCE_MANAGER_MAGIC = 0xbeefcace;
const generatedName = (index: number): string => `resource-${index.toString(36)}`;
const generatedValue = (index: number): string => `value-${index.toString(36)}`;

void test("resource strings cannot consume a neighboring value", async () => {
  const payload = makeDotNetResources([
    { name: "broken", value: [1, 8, 65] }, // String claims eight bytes but owns only one.
    { name: "intact", value: stringResourceValue("survives") }
  ]);
  const issues: string[] = [];

  const values = await parseDotNetResources(payload, issues);

  assert.strictEqual(values?.[0]?.value, null);
  assert.ok(values?.[0]?.issues?.length);
  assert.strictEqual(values?.[1]?.value, "survives");
});

void test("resource names cannot consume the data section", async () => {
  const payload = makeDotNetResources([{ name: "name", value: stringResourceValue("text") }]);
  const view = new DataView(payload.buffer);
  const namesOffset = runtimeTableOffset() + 12;
  payload[namesOffset] = view.getUint32(runtimeTableOffset() + 8, true) - namesOffset;

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.ok(parsed.issues.length);
});

void test("unsupported resource-set versions are not decoded as v2", async () => {
  const payload = makeDotNetResources([{ name: "name", value: stringResourceValue("text") }]);
  new DataView(payload.buffer).setInt32(runtimeHeaderOffset(), 3, true);

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.ok(parsed.issues.some(issue => issue.includes("Unsupported")));
});

void test("a backwards data section is rejected", async () => {
  const payload = makeDotNetResources([{ name: "name", value: stringResourceValue("text") }]);
  new DataView(payload.buffer).setInt32(runtimeTableOffset() + 8, 0, true);

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.ok(parsed.issues.length);
});

void test("custom ResourceReader headers are not decoded using the standard layout", async () => {
  const payload = makeDotNetResources([{ name: "name", value: stringResourceValue("text") }]);
  payload[13] = "X".charCodeAt(0);

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.match(parsed.issues.join(" "), /ResourceReader/);
});

void test("odd UTF-16 names are rejected", async () => {
  const payload = makeDotNetResources([{ name: "name", value: stringResourceValue("text") }]);
  payload[runtimeTableOffset() + 12] = 7;

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.ok(parsed.issues.length);
});

void test("duplicate names produce a diagnostic", async () => {
  const payload = makeDotNetResources([
    { name: "same", value: stringResourceValue("first") },
    { name: "same", value: stringResourceValue("second") }
  ]);

  const parsed = await parseWithIssues(payload);

  assert.match(parsed.issues.join(" "), /duplicate name/);
});

const parseWithIssues = async (payload: Uint8Array): Promise<{ issues: string[]; values: unknown }> => {
  const issues: string[] = [];
  return { issues, values: await parseDotNetResources(payload, issues) };
};

void test("parseDotNetResources returns null for non-resource payloads", async () => {
  const payload = new Uint8Array(Uint32Array.BYTES_PER_ELEMENT);

  const parsed = await parseWithIssues(payload);

  assert.strictEqual(parsed.values, null);
  assert.deepStrictEqual(parsed.issues, []);
});

void test("parseDotNetResources decodes multiple named string values", async () => {
  const entries = [
    { name: generatedName(0), value: stringResourceValue(generatedValue(0)) },
    { name: generatedName(1), value: stringResourceValue(generatedValue(1)) }
  ];

  const parsed = await parseWithIssues(makeDotNetResources(entries));

  assert.deepStrictEqual(parsed.values, [
    { name: generatedName(0), type: "String", value: generatedValue(0), opaque: false },
    { name: generatedName(1), type: "String", value: generatedValue(1), opaque: false }
  ]);
});

void test("parseDotNetResources reports truncated ResourceManager headers", async () => {
  const payload = new Uint8Array(Uint32Array.BYTES_PER_ELEMENT);
  new DataView(payload.buffer).setUint32(0, RESOURCE_MANAGER_MAGIC, true);

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.ok(parsed.issues.some(issue => issue.includes("ResourceManager header is truncated")));
});

void test("parseDotNetResources reports headers extending past payload", async () => {
  const payload = new Uint8Array(RESOURCE_MANAGER_FIXED_HEADER_SIZE);
  const view = new DataView(payload.buffer);
  view.setUint32(0, RESOURCE_MANAGER_MAGIC, true);
  view.setInt32(Uint32Array.BYTES_PER_ELEMENT * 2, payload.length, true);

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.ok(parsed.issues.some(issue => issue.includes("extends past payload")));
});

void test("parseDotNetResources rejects unreasonable entry counts", async () => {
  const payload = makeDotNetResources([]);
  const view = new DataView(payload.buffer);
  view.setInt32(runtimeHeaderOffset() + Uint32Array.BYTES_PER_ELEMENT, Uint16Array.BYTES_PER_ELEMENT ** 14, true);

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.ok(parsed.issues.some(issue => issue.includes("unreasonable")));
});

void test("parseDotNetResources reports truncated name tables", async () => {
  const payload = makeDotNetResources([
    { name: generatedName(2), value: stringResourceValue(generatedValue(2)) }
  ]);
  const view = new DataView(payload.buffer);
  view.setUint32(runtimeTableOffset() + Uint32Array.BYTES_PER_ELEMENT, payload.length, true);

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.ok(parsed.issues.some(issue => issue.includes("name 1 is truncated")));
});

void test("resource user types stay opaque and v1 integer types are decoded", async () => {
  const issues: string[] = [];

  const custom = await parseDotNetResources(makeDotNetResources(
    [{ name: "custom", value: [64, 1, 2, 3] }], ["Example.Type, Example.Assembly"]), issues);
  const integer = await parseDotNetResources(makeDotNetResources(
    [{ name: "number", value: [0, 42, 0, 0, 0] }], ["System.Int32, mscorlib"], 1), issues);

  assert.strictEqual(custom?.[0]?.type, "Example.Type, Example.Assembly");
  assert.strictEqual(custom?.[0]?.opaque, true);
  assert.strictEqual(integer?.[0]?.value, 42);
  assert.deepStrictEqual(issues, []);
});

void test("negative data and name offsets are rejected", async () => {
  const payload = makeDotNetResources([{ name: "name", value: stringResourceValue("text") }]);
  new DataView(payload.buffer).setInt32(runtimeTableOffset() + 4, -1, true);

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.ok(parsed.issues.length);
});

void test("bad manager versions are rejected", async () => {
  const payload = makeDotNetResources([]);
  new DataView(payload.buffer).setInt32(4, -1, true);

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.match(parsed.issues.join(" "), /version/);
});

void test("shared data offsets preserve names while reusing the decoded value", async () => {
  const payload = makeDotNetResources([
    { name: "first", value: stringResourceValue("shared") },
    { name: "second", value: stringResourceValue("shared") }
  ]);
  const view = new DataView(payload.buffer);
  const namesOffset = runtimeTableOffset() + 20;
  const secondOffset = view.getUint32(runtimeTableOffset() + 12, true);
  const secondNameLength = payload[namesOffset + secondOffset]!;
  view.setInt32(namesOffset + secondOffset + 1 + secondNameLength, 0, true);

  const parsed = await parseDotNetResources(payload, []);

  assert.deepStrictEqual(parsed?.map(value => value.name), ["first", "second"]);
  assert.deepStrictEqual(parsed?.map(value => value.value), ["shared", "shared"]);
});

const truncatedFixture = makeDotNetResources([{ name: "entry", value: stringResourceValue("text") }]);

void test("broken header strings and type names are diagnosed", async () => {
  const header = makeDotNetResources([]);
  header[12] = 255;
  const types = makeDotNetResources([], ["Example.Type"]);
  types[runtimeHeaderOffset() + 12] = 255;

  const badHeader = await parseWithIssues(header);
  const badTypes = await parseWithIssues(types);

  assert.match(badHeader.issues.join(" "), /type names are truncated/);
  assert.match(badTypes.issues.join(" "), /type-name table is truncated/);
});

void test("truncated type codes produce a value diagnostic", async () => {
  const values = await parseDotNetResources(makeDotNetResources([{ name: "bad", value: [128] }]), []);

  assert.strictEqual(values?.[0]?.value, null);
  assert.match(values?.[0]?.issues?.join(" ") ?? "", /type code is truncated/);
});

void test("header versions above one skip their declared extension bytes", async () => {
  const payload = makeDotNetResources([]);
  new DataView(payload.buffer).setInt32(4, 2, true);

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.deepStrictEqual(parsed.issues, []);
});

void test("inconsistent v1 header lengths are warned about while reading actual strings", async () => {
  const payload = makeDotNetResources([]);
  new DataView(payload.buffer).setInt32(8, 0, true);

  const parsed = await parseWithIssues(payload);

  assert.deepStrictEqual(parsed.values, []);
  assert.match(parsed.issues.join(" "), /inconsistent/);
});

for (let cut = 4; cut < truncatedFixture.length; cut += 1) {
  void test(`resource truncation at byte ${cut} is diagnosed without throwing`, async () => {
    const issues: string[] = [];

    const values = await parseDotNetResources(truncatedFixture.subarray(0, cut), issues);

    assert.ok(issues.length || values?.some(value => value.issues?.length));
  });
}
