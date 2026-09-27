import assert from "node:assert/strict";
import { test } from "node:test";
import { addRegistryPreview } from "../../../../../../analyzers/pe/resources/preview/registry.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../../analyzers/pe/index.js";
import { createPeRegistryFile } from "../../../../../fixtures/pe-registry-file.js";

// 1 MiB (1024*1024 bytes) straddles the removed preview cap; the final key must survive.
// The Registrar CLSID/ProgID are from Microsoft's example:
// https://learn.microsoft.com/en-us/cpp/atl/registry-scripting-examples
void test("REGISTRY parses the Microsoft Registrar example with symbolic module paths", () => {
  // Microsoft Learn: registry-scripting-examples, Registrar COM server example.
  const result = addRegistryPreview(new TextEncoder().encode(
    "HKCR { NoRemove CLSID { ForceRemove {44EC053A-400F-11D0-9DCD-00A0C90391D3} " +
    "= s 'ATL Registrar Class' { ProgID = s 'ATL.Registrar' " +
    "InprocServer32 = s '%MODULE%' { val ThreadingModel = s 'Apartment' } } } }"
  ), "REGISTRY", 65001);
  assert.equal(result?.preview?.previewKind, "registry");
  assert.equal(result?.preview?.registry?.roots[0]?.name, "HKCR");
  const classKey = result?.preview?.registry?.roots[0]?.children[0]?.children[0];
  assert.equal(classKey?.directive, "ForceRemove");
  assert.deepEqual(classKey?.value, { type: "REG_SZ", data: "ATL Registrar Class" });
  assert.deepEqual(classKey?.children[1]?.value, { type: "REG_SZ", data: "%MODULE%" });
  assert.equal(classKey?.children[1]?.children[0]?.directive, "val");
  assert.equal(result?.issues, undefined);
});

void test("full PE parsing attaches deep registration analysis to the named REGISTRY resource", async () => {
  const parsed = await parsePe(createPeRegistryFile());
  assert.ok(parsed && isPeWindowsParseResult(parsed));
  const entry = parsed.resources?.detail?.find(group => group.typeName === "REGISTRY")
    ?.entries[0]?.langs[0];
  assert.equal(entry?.registry?.roots[0]?.name, "HKCR");
  assert.match(entry?.previewIssues?.join(" ") ?? "", /missing assignment/);
});

void test("standalone preview reads declarations beyond one MiB with missing code page", () => {
  const bytes = new TextEncoder().encode(" ".repeat(1024 * 1024) + "HKCU { Last }");
  const result = addRegistryPreview(bytes, "RGS", undefined);
  assert.equal(result?.preview?.registry?.roots[0]?.name, "HKCU");
  assert.equal(result?.preview?.registry?.roots[0]?.children[0]?.name, "Last");
  assert.equal(result?.issues, undefined);
});

void test("every declaration retains its diagnostic", () => {
  const result = addRegistryPreview(new TextEncoder().encode("HKCU { " +
    "val Name = q 'data' ".repeat(200) + "}"), "REGISTRY", 65001);
  assert.equal(result?.issues?.length, 200);
  assert.match(result?.issues?.at(-1) ?? "", /unsupported/);
});

void test("resource-level preprocessing and COM diagnostics are attached to previews", () => {
  const result = addRegistryPreview(new TextEncoder().encode(
    "HKCR { CLSID { Invalid } Key = s '%unclosed' }"), "REGISTRY", 65001);
  assert.match(result?.issues?.join(" ") ?? "", /GUID/);
  assert.match(result?.issues?.join(" ") ?? "", /unclosed replacement/);
});

void test("REGISTRY keeps an empty or malformed resource reviewable", () => {
  const empty = addRegistryPreview(new Uint8Array(), "REGISTRY", 0);
  const broken = addRegistryPreview(new TextEncoder().encode("HKCR { val Name ="), "REGISTRY", 0);
  assert.equal(empty?.preview?.registry?.roots.length, 0);
  assert.match(empty?.issues?.join(" ") ?? "", /empty/i);
  assert.match(broken?.issues?.join(" ") ?? "", /missing|unclosed/i);
  assert.equal(addRegistryPreview(new Uint8Array(), "REGINST", 0), null);
});

void test("standalone preview honors a non-default ANSI code page", () => {
  const data = new Uint8Array([...new TextEncoder().encode("HKCU { '"), 0xcf,
    ...new TextEncoder().encode("' }")]);
  assert.equal(addRegistryPreview(data, "registry", 1251)?.preview?.registry?.roots[0]?.children[0]?.name, "П");
});
