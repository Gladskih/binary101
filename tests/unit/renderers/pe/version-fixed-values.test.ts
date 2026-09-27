import assert from "node:assert/strict";
import { test } from "node:test";
import { versionFixedRows } from "../../../../renderers/pe/version-fixed-values.js";
import { renderVersionPreview } from "../../../../renderers/pe/resource-preview-version.js";

const base = { structVersionRaw: 0 };

void test("renders flags, mask, OS, type, subtype and full binary date", () => {
  const html = renderVersionPreview({ fixedFileInfo: { ...base,
    fileFlagsMask: 0x3f, fileFlags: 0x8000003f, fileOS: 0x40004,
    fileType: 3, fileSubtype: 4, fileDateMS: 0x12345678, fileDateLS: 0xabcdef01
  } });

  assert.match(html, /VS_FF_DEBUG.*VS_FF_PRERELEASE.*VS_FF_PATCHED.*VS_FF_PRIVATEBUILD/);
  assert.match(html, /VS_FF_INFOINFERRED.*VS_FF_SPECIALBUILD.*unknown 0x80000000/);
  assert.match(html, /VOS_NT.*VOS__WINDOWS32/);
  assert.match(html, /VFT_DRV/);
  assert.match(html, /VFT2_DRV_DISPLAY/);
  assert.match(html, /0x12345678 \/ 0xabcdef01/);
});

void test("handles legacy partial info, unknown values and context-sensitive subtypes", () => {
  assert.deepEqual(versionFixedRows(base), []);
  assert.match(JSON.stringify(versionFixedRows({ ...base, fileFlagsMask: 0 })), /VFT_UNKNOWN/);
  assert.match(JSON.stringify(versionFixedRows({ ...base, fileFlagsMask: 0, fileType: 4,
    fileSubtype: 3 })), /VFT2_FONT_TRUETYPE/);
  assert.match(JSON.stringify(versionFixedRows({ ...base, fileFlagsMask: 0, fileType: 3,
    fileSubtype: 0 })), /VFT2_UNKNOWN/);
  assert.match(JSON.stringify(versionFixedRows({ ...base, fileFlagsMask: 0, fileType: 99,
    fileOS: 0xffffffff, fileSubtype: 99 })), /reserved/);
});
