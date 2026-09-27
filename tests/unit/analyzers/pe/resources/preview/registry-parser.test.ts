import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRegistryScript, registryRootName } from "../../../../../../analyzers/pe/resources/preview/registry-parser.js";

// 10000 nested keys stress stack safety; 10001 closing braces include the hive's block.
// This is a regression workload, not a documented ATL nesting restriction.
for (const [short, long] of [
    ["HKCR", "HKEY_CLASSES_ROOT"], ["HKCU", "HKEY_CURRENT_USER"],
    ["HKLM", "HKEY_LOCAL_MACHINE"], ["HKU", "HKEY_USERS"],
    ["HKPD", "HKEY_PERFORMANCE_DATA"], ["HKDD", "HKEY_DYN_DATA"],
    ["HKCC", "HKEY_CURRENT_CONFIG"]
  ] as const) {
  void test(`ATL hive ${short} accepts mixed case and the long name`, () => {
    assert.equal(registryRootName(short.toLowerCase()), long);
    assert.equal(registryRootName(long), long);
  });
}

void test("multiple hives and mixed-case directives preserve the tree", () => {
  assert.equal(registryRootName("__proto__"), null);
  const issues: string[] = [];
  const script = parseRegistryScript("hkcu { nOrEmOvE Shared { vAl '' = s '' } Delete Old } HKLM { }", issues);
  assert.equal(script.roots.length, 2);
  assert.equal(script.roots[0]?.children[0]?.directive, "NoRemove");
  assert.equal(script.roots[0]?.children[0]?.children[0]?.name, "");
  assert.equal(script.roots[0]?.children[1]?.directive, "Delete");
  assert.deepEqual(issues, []);
});

const deepestNode = (node: ReturnType<typeof parseRegistryScript>["roots"][number] | undefined) => {
  let current = node;
  while (current?.children.length) current = current.children[0];
  return current;
};

for (const [text, expected] of [
  ["HKCR", /opening brace/], ["Unknown { }", /root hive/],
  ["NoRemove HKCR { }", /root hive/], ["HKCR = s 'value' { }", /root hive cannot/],
  ["HKCR { val Name }", /requires an assignment/], ["HKCR { ForceRemove }", /missing key/],
  ["HKCR { '' }", /empty key/], ["HKCR { 'One\\Two' }", /compound key/],
  ["HKCR { Delete Old = s 'ignored' }", /ignored/],
  ["HKCR { val Name = s 'value' { Nested } }", /cannot contain/],
  ["HKCR { Delete Old { Nested } }", /cannot contain/],
  ["HKCR { = { }", /unexpected token/], ["}", /unexpected token/],
  ["HKCR { Key = d }", /missing assignment/], ["HKCR { Key =", /missing assignment/],
  ["HKCR { Key {", /unclosed/], ["HKCR{ }", /root hive/],
  ["HKCR { ForceRemove", /missing key/]
] as const) {
  void test(`malformed RGS ${text} produces diagnostics`, () => {
    const issues: string[] = [];
    assert.doesNotThrow(() => parseRegistryScript(text, issues));
    assert.match(issues.join(" "), expected);
  });
}

void test("deep nesting retains every key without recursive stack growth", () => {
  const issues: string[] = [];
  const script = parseRegistryScript("HKCR { " + "Key { ".repeat(10000) +
    "val Data = s 'ok' " + "} ".repeat(10001) + "HKCU { Good }", issues);
  assert.equal(deepestNode(script.roots[0])?.name, "Data");
  assert.deepEqual(deepestNode(script.roots[0])?.value, { type: "REG_SZ", data: "ok" });
  assert.deepEqual(issues, []);
  assert.equal(script.roots.at(-1)?.name, "HKCU");
  assert.equal(script.roots.at(-1)?.children[0]?.name, "Good");
});

void test("quoted structural characters stay key names and not blocks", () => {
  const issues: string[] = [];
  const script = parseRegistryScript("HKCR { '{' '}' '=' }", issues);
  assert.deepEqual(script.roots[0]?.children.map(node => node.name), ["{", "}", "="]);
  assert.match(issues.join(" "), /quoted structural/);
});

void test("parser diagnostics preserve the exact source line and column", () => {
  const issues: string[] = [];
  parseRegistryScript("HKCU\n{ val Missing }", issues);
  assert.deepEqual(issues, ["ATL RGS 2:3: named value requires an assignment."]);
});

void test("stray opening braces produce warnings and do not become key declarations", () => {
  const issues: string[] = [];
  const script = parseRegistryScript("HKCU { { } }", issues);
  assert.deepEqual(script.roots[0]?.children, []);
  assert.deepEqual(issues, ["ATL RGS 1:8: unexpected token '{'.", "ATL RGS 1:12: unexpected token '}'."]);
});
