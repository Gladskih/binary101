import assert from "node:assert/strict";
import { test } from "node:test";
import { validateVersionInfo } from "../../../../../../analyzers/pe/resources/preview/version-validation.js";

void test("compares numeric versions per language and leaves descriptive versions alone", () => {
  assert.deepEqual(validateVersionInfo({ fileVersionString: "1.2.3.4", stringValues: [
    { table: "040904B0", key: "FileVersion", value: "01, 2, 3, 4" },
    { table: "040904B0", key: "FileVersion", value: "1.2.3.4 (release)" },
    { table: "040704B0", key: "CompanyName", value: "different" }
  ] }), []);
  assert.match(validateVersionInfo({ productVersionString: "1.2.3.4", stringValues: [
    { table: "040704B0", key: "ProductVersion", value: "1.2.3.5" }
  ] })[0] ?? "", /040704B0 ProductVersion.*differs/);
  assert.deepEqual(validateVersionInfo({}), []);
});

void test("validates only masked build flags and requires build strings", () => {
  const fixedFileInfo = { structVersionRaw: 0, structVersionMajor: 0, structVersionMinor: 0,
    fileFlags: 0x38, fileFlagsMask: 0x38 }; // PRIVATEBUILD | INFOINFERRED | SPECIALBUILD.
  assert.equal(validateVersionInfo({ fixedFileInfo }).length, 3);
  assert.equal(validateVersionInfo({ fixedFileInfo, stringValues: [
    { table: "040904B0", key: "PrivateBuild", value: "private" },
    { table: "040904B0", key: "SpecialBuild", value: "special" }
  ] }).length, 1);
  assert.deepEqual(validateVersionInfo({ fixedFileInfo: { ...fixedFileInfo, fileFlagsMask: 0 } }), []);
});
