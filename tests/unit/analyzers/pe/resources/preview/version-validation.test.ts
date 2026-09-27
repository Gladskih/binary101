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
  const fixedFileInfo = { structVersionRaw: 0,
    fileFlags: 0x38, fileFlagsMask: 0x38 }; // PRIVATEBUILD | INFOINFERRED | SPECIALBUILD.
  assert.equal(validateVersionInfo({ fixedFileInfo }).length, 3);
  assert.equal(validateVersionInfo({ fixedFileInfo, stringValues: [
    { table: "040904B0", key: "PrivateBuild", value: "private" },
    { table: "040904B0", key: "SpecialBuild", value: "special" }
  ] }).length, 1);
  assert.deepEqual(validateVersionInfo({ fixedFileInfo: { ...fixedFileInfo, fileFlagsMask: 0 } }), []);
});

void test("compares whitespace and multi-digit numeric versions but rejects decorated strings", () => {
  const stringValues = [
    { table: "lang", key: "FileVersion", value: " 11 , 22 , 33 , 44 " },
    { table: "lang", key: "ProductVersion", value: " 11 . 22 . 33 . 44 " }
  ];
  assert.deepEqual(validateVersionInfo({ fileVersionString: "1.2.3.4",
    productVersionString: "1.2.3.4", stringValues }), [
    "lang FileVersion ( 11 , 22 , 33 , 44 ) differs from fixed version 1.2.3.4.",
    "lang ProductVersion ( 11 . 22 . 33 . 44 ) differs from fixed version 1.2.3.4."
  ]);
  assert.deepEqual(validateVersionInfo({ fileVersionString: "9.9.9.9", stringValues: [
    { table: "lang", key: "FileVersion", value: "prefix 1.2.3.4" },
    { table: "lang", key: "FileVersion", value: "1.2.3.4 suffix" }
  ] }), []);
});

void test("requires nonempty matching build keys and checks each flag independently", () => {
  const fixedFileInfo = { structVersionRaw: 0,
    fileFlags: 0x38, fileFlagsMask: 0x3f };
  const stringValues = [
    { table: "lang", key: "PrivateBuild", value: "   " },
    { table: "lang", key: "SpecialBuild", value: "   " },
    { table: "lang", key: "CompanyName", value: "valid but unrelated" }
  ];
  assert.deepEqual(validateVersionInfo({ fixedFileInfo, stringValues }), [
    "VS_FF_PRIVATEBUILD is set without a PrivateBuild string.",
    "VS_FF_SPECIALBUILD is set without a SpecialBuild string.",
    "VS_FF_INFOINFERRED must not be set in a VERSION resource."
  ]);
  assert.deepEqual(validateVersionInfo({ fixedFileInfo: { ...fixedFileInfo, fileFlags: 0x08 },
    stringValues: [{ table: "lang", key: "SpecialBuild", value: "present" }] }),
  ["VS_FF_PRIVATEBUILD is set without a PrivateBuild string."]);
  assert.deepEqual(validateVersionInfo({ fixedFileInfo: { ...fixedFileInfo, fileFlags: 0x20 },
    stringValues: [{ table: "lang", key: "PrivateBuild", value: "present" }] }),
  ["VS_FF_SPECIALBUILD is set without a SpecialBuild string."]);
});
