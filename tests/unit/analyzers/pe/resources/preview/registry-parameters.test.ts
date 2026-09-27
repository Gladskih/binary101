import assert from "node:assert/strict";
import { test } from "node:test";
import { registryParameters } from "../../../../../../analyzers/pe/resources/preview/registry-parameters.js";

// PreProcessBuffer's TCHAR buf[32] reserves one NUL: exactly 31 characters fit, 32 do not.
// https://github.com/adzm/atlmfc/blob/master/include/statreg.h (PreProcessBuffer)

void test("replacement scanning handles escaped percent and case-insensitive names", () => {
  const issues: string[] = [];
  assert.deepEqual(registryParameters("%% %MODULE% %module% %MODULE_RAW% %Custom% %%%CLSID%", issues),
    ["MODULE", "MODULE_RAW", "CUSTOM", "CLSID"]);
  assert.deepEqual(issues, []);
  assert.deepEqual(registryParameters("plain", []), []);
});
void test("replacement scanning diagnoses incomplete and overlong names", () => {
  const issues: string[] = [];
  assert.equal(registryParameters(`%${"x".repeat(32)}% %broken`, issues).length, 1);
  assert.match(issues.join(" "), /31 characters/);
  assert.match(issues.join(" "), /unclosed/);
});

void test("ATL replacement names may contain exactly 31 characters", () => {
  const issues: string[] = [];
  assert.deepEqual(registryParameters(`%${"x".repeat(31)}%`, issues), ["X".repeat(31)]);
  assert.deepEqual(issues, []);
});
