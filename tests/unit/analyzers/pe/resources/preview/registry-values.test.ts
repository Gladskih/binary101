import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRegistryValue } from "../../../../../../analyzers/pe/resources/preview/registry-values.js";

// Unsigned DWORD boundaries: 2^32 - 1 = 4294967295; first excluded = 4294967296.
// https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
// Hex byte oracles 00/AA/FF = 0/170/255, two digits per octet:
// https://www.rfc-editor.org/rfc/rfc4648.html#section-8
void test("ATL s/d/m/b types are case-insensitive and use ATL data syntax", () => {
  const issues: string[] = [];
  assert.deepEqual(parseRegistryValue("S", "C:\\path %MODULE%", issues),
    { type: "REG_SZ", data: "C:\\path %MODULE%" });
  assert.deepEqual(parseRegistryValue("D", "4294967295", issues),
    { type: "REG_DWORD", data: 4294967295 }); // ULONG maximum, AddValue uses VarUI4FromStr.
  assert.deepEqual(parseRegistryValue("d", " +000 ", issues), { type: "REG_DWORD", data: 0 });
  assert.deepEqual(parseRegistryValue("m", "first\\0second", issues),
    { type: "REG_MULTI_SZ", data: ["first", "second"] });
  assert.deepEqual(parseRegistryValue("B", "00aAFF", issues),
    { type: "REG_BINARY", data: new Uint8Array([0, 170, 255]) });
  assert.deepEqual(parseRegistryValue("b", "", issues), { type: "REG_BINARY", data: new Uint8Array() });
  assert.deepEqual(issues, []);
});

for (const source of ["-1", "4294967296", "0x20", "garbage", "1.5", "", "1e2"]) {
  void test(`DWORD '${source}' remains unresolved rather than guessed`, () => {
    const issues: string[] = [];
    assert.deepEqual(parseRegistryValue("d", source, issues), { type: "unresolved", tag: "d", source });
    assert.deepEqual(issues, ["ATL RGS: DWORD is out of range or requires OLE/locale-specific coercion."]);
  });
}
for (const source of ["0", "GG", "00 11"]) {
  void test(`binary '${source}' is invalid`, () => {
    const issues: string[] = [];
    assert.equal(parseRegistryValue("b", source, issues).type, "unresolved");
    assert.deepEqual(issues, ["ATL RGS: binary value must contain complete hexadecimal byte pairs."]);
  });
}
void test("runtime DWORD/binary parameters and unknown tags remain symbolic", () => {
  const issues: string[] = [];
  assert.deepEqual(parseRegistryValue("d", "%NUMBER%", issues),
    { type: "unresolved", tag: "d", source: "%NUMBER%" });
  assert.deepEqual(parseRegistryValue("b", "%BYTES%", issues),
    { type: "unresolved", tag: "b", source: "%BYTES%" });
  assert.deepEqual(issues, []);
  assert.deepEqual(parseRegistryValue("q", "10", issues),
    { type: "unresolved", tag: "q", source: "10" });
  assert.deepEqual(issues, ["ATL RGS: unsupported registry value type 'q'."]);
});

void test("MULTI_SZ ends at the first empty string and warns if later entries are hidden", () => {
  const issues: string[] = [];
  assert.deepEqual(parseRegistryValue("m", "one\\0two\\0\\0", issues),
    { type: "REG_MULTI_SZ", data: ["one", "two"] });
  assert.deepEqual(parseRegistryValue("m", "", issues), { type: "REG_MULTI_SZ", data: [] });
  assert.deepEqual(issues, []);
  assert.deepEqual(parseRegistryValue("m", "one\\0\\0hidden", issues),
    { type: "REG_MULTI_SZ", data: ["one"] });
  assert.match(issues.join(" "), /empty string/);
  assert.deepEqual(parseRegistryValue("m", "\\0hidden", issues),
    { type: "REG_MULTI_SZ", data: [] });
  assert.deepEqual(issues, ["ATL RGS: MULTI_SZ data after its first empty string is not stored.",
    "ATL RGS: MULTI_SZ data after its first empty string is not stored."]);
});
