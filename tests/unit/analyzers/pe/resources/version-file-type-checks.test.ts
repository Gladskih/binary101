import assert from "node:assert/strict";
import { test } from "node:test";
import { attachVersionFileTypeChecks } from
  "../../../../../analyzers/pe/resources/version-file-type-checks.js";
import type { PeResources } from "../../../../../analyzers/pe/resources/index.js";

const resources = (fileType: number): PeResources => ({ top: [], detail: [
  { typeName: "VERSION", entries: [{ id: 1, name: null, langs: [{
    lang: 1033, dataRVA: 1, size: 1, codePage: 0, dataFileOffset: 0, reserved: 0,
    versionInfo: { fixedFileInfo: { structVersionRaw: 0x10000, fileType } }
  }] }] }
] });

void test("confirms VERSION app and DLL file types against the COFF DLL flag", () => {
  // VFT_APP=1, VFT_DLL=2, IMAGE_FILE_DLL=0x2000.
  // https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
  // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
  const app = attachVersionFileTypeChecks(resources(1), 0);
  const dll = attachVersionFileTypeChecks(resources(2), 0x2000);
  assert.equal(app?.crossChecks?.[0]?.status, "confirmed");
  assert.equal(dll?.crossChecks?.[0]?.status, "confirmed");
  assert.equal(app?.crossChecks?.[0]?.detail,
    "VERSION VFT_APP agrees with COFF IMAGE_FILE_DLL (clear).");
  assert.equal(dll?.crossChecks?.[0]?.detail,
    "VERSION VFT_DLL agrees with COFF IMAGE_FILE_DLL (set).");
  assert.equal(dll?.crossChecks?.[0]?.subject, "#1 / LANG 1033");
});

void test("warns on contradictory VERSION and COFF file types", () => {
  const app = attachVersionFileTypeChecks(resources(1), 0x2000);
  const dll = attachVersionFileTypeChecks(resources(2), 0);
  assert.equal(app?.crossChecks?.[0]?.status, "warning");
  assert.equal(dll?.crossChecks?.[0]?.status, "warning");
  assert.equal(app?.crossChecks?.[0]?.detail,
    "VERSION VFT_APP disagrees with COFF IMAGE_FILE_DLL (set).");
  assert.equal(dll?.crossChecks?.[0]?.detail,
    "VERSION VFT_DLL disagrees with COFF IMAGE_FILE_DLL (clear).");
});

void test("labels named and neutral VERSION entries and ignores other resource kinds", () => {
  const data = resources(2);
  data.detail[0]!.entries[0]!.name = "Build";
  data.detail[0]!.entries[0]!.langs[0]!.lang = null;
  assert.equal(attachVersionFileTypeChecks(data, 0x2000)?.crossChecks?.[0]?.subject,
    "Build / LANG neutral");
  data.detail[0]!.entries[0]!.name = null;
  data.detail[0]!.entries[0]!.id = null;
  assert.equal(attachVersionFileTypeChecks(data, 0x2000)?.crossChecks?.[0]?.subject,
    "#? / LANG neutral");
  data.detail[0]!.typeName = "RCDATA";
  assert.equal(attachVersionFileTypeChecks(data, 0x2000)?.crossChecks, undefined);
});

void test("does not guess for drivers, missing fixed info, or absent resources", () => {
  const driver = resources(3);
  assert.equal(attachVersionFileTypeChecks(driver, 0x2000)?.crossChecks, undefined);
  delete driver.detail[0]!.entries[0]!.langs[0]!.versionInfo;
  assert.equal(attachVersionFileTypeChecks(driver, 0)?.crossChecks, undefined);
  assert.equal(attachVersionFileTypeChecks(null, 0), null);
});

void test("preserves existing dialog checks while checking multiple VERSION variants", () => {
  const data = resources(2);
  data.crossChecks = [{ status: "confirmed", subject: "DIALOG #1", detail: "MENU matches." }];
  data.detail[0]!.entries[0]!.langs.push({
    ...data.detail[0]!.entries[0]!.langs[0]!, lang: 1041
  });
  assert.equal(attachVersionFileTypeChecks(data, 0x2000)?.crossChecks?.length, 3);
  assert.equal(data.crossChecks.length, 1);
});
