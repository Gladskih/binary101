"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePermissionSet } from "../../../../../../analyzers/pe/clr/metadata-security.js";

const binary = (payload: number[]): Uint8Array => Uint8Array.of(0x2e, 1, 1, 65, payload.length, ...payload);

void test("decodes UTF-16 XML permission sets without executing XML", () => {
  assert.deepEqual(parsePermissionSet(Uint8Array.of(60, 0, 47, 0, 62, 0), "Security"),
    { kind: "security", encoding: "xml", xml: "</>" });
  assert.ok(parsePermissionSet(new Uint8Array(), "Security").issues?.length);
  assert.ok(parsePermissionSet(Uint8Array.of(60), "Security").issues?.length);
});

void test("decodes compressed security counts and named arguments", () => {
  // Runtime binary format: '.', NumAttrs, UTF8 type name, payload length, NumNamed.
  assert.deepEqual(parsePermissionSet(binary([1, 0x54, 8, 1, 66, 0xff, 0xff, 0xff, 0xff]), "Security"), {
    kind: "security", encoding: "binary", attributes: [{ typeName: "A", namedArguments: [
      { kind: "property", type: "i4", name: "B", value: -1 }
    ] }]
  });
  assert.deepEqual(parsePermissionSet(Uint8Array.of(0x2e, 0), "Security"),
    { kind: "security", encoding: "binary", attributes: [] });
  assert.deepEqual(parsePermissionSet(binary([0]), "Security"),
    { kind: "security", encoding: "binary", attributes: [{ typeName: "A", namedArguments: [] }] });
});

void test("resolves known named enum widths in security attributes", () => {
  const value = parsePermissionSet(binary([1, 0x53, 0x55, 1, 69, 1, 66, 0xff]), "Security", new Map([["E", "i1"]]));
  assert.equal(value.encoding, "binary");
  assert.deepEqual(value.encoding === "binary" && value.attributes[0]?.namedArguments,
    [{ kind: "field", type: "enum E", name: "B", value: -1 }]);
});

for (const bytes of [Uint8Array.of(0x2e), Uint8Array.of(0x2e, 1), Uint8Array.of(0x2e, 1, 0),
  Uint8Array.of(0x2e, 1, 0, 2, 0), Uint8Array.of(0x2e, 0, 7)]) {
  void test(`warns on incomplete binary envelope ${Array.from(bytes)}`, () => {
    assert.ok(parsePermissionSet(bytes, "Security").issues?.length);
  });
}

for (const payload of [[], [1], [1, 0x52], [0, 7], [1, 0x54, 0x55, 1, 69, 1, 66, 7]]) {
  void test(`reports malformed or unresolved argument payload ${payload}`, () => {
    const value = parsePermissionSet(binary(payload), "Security");
    assert.ok(value.encoding === "binary" && value.attributes[0]?.issues?.length);
  });
}

void test("uses entry lengths to continue after an unresolved enum in an earlier attribute", () => {
  const value = parsePermissionSet(Uint8Array.of(0x2e, 2,
    1, 65, 8, 1, 0x54, 0x55, 1, 69, 1, 66, 7,
    1, 67, 6, 1, 0x54, 2, 1, 68, 1), "Security");
  assert.equal(value.encoding, "binary");
  assert.equal(value.issues, undefined);
  assert.ok(value.encoding === "binary");
  assert.equal(value.attributes.length, 2);
  assert.equal(value.attributes[0]?.typeName, "A");
  assert.match(value.attributes[0]?.issues?.[0] ?? "", /underlying type is unresolved/);
  assert.deepEqual(value.attributes[1], { typeName: "C", namedArguments: [
    { kind: "property", type: "bool", name: "D", value: true }
  ] });
});

void test("diagnoses envelope counts independently of truncated entry payloads", () => {
  assert.deepEqual(parsePermissionSet(Uint8Array.of(0x2e), "Security"), {
    kind: "security", encoding: "binary", attributes: [],
    issues: ["Security: compressed integer is malformed or truncated."]
  });
  assert.deepEqual(parsePermissionSet(Uint8Array.of(0x2e, 1, 0xff), "Security"), {
    kind: "security", encoding: "binary", attributes: [],
    issues: ["Security: compressed integer is malformed or truncated.", "Security: security attribute count is incomplete."]
  });
  const empty = parsePermissionSet(binary([]), "Security");
  assert.ok(empty.encoding === "binary");
  assert.deepEqual(empty.attributes[0]?.issues, ["Security A: compressed integer is malformed or truncated."]);
  const trailing = parsePermissionSet(binary([0, 7]), "Security");
  assert.ok(trailing.encoding === "binary");
  assert.deepEqual(trailing.attributes[0]?.issues, ["Security A: named arguments have 1 trailing byte(s)."]);
  const truncated = parsePermissionSet(binary([1]), "Security");
  assert.ok(truncated.encoding === "binary");
  assert.match(truncated.attributes[0]?.issues?.at(-1) ?? "", /named argument count is incomplete/);
  assert.deepEqual(parsePermissionSet(new Uint8Array(), "Security"), { kind: "security", encoding: "xml", xml: "",
    issues: ["Security: permission set is empty."] });
});
