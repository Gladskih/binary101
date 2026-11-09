import assert from "node:assert/strict";
import { test } from "node:test";
import { versionFixedRows } from "../../../../renderers/pe/version-fixed-values.js";
import { renderVersionPreview } from "../../../../renderers/pe/resource-preview-version.js";

const base = { structVersionRaw: 0 };

const chipState = (html: string, label: string): string | undefined =>
  new RegExp(`<span class="opt (sel|dim)" [^>]*>${label}</span>`).exec(html)?.[1];

// Independent expected enum codes from VS_FIXEDFILEINFO / Windows SDK verrsrc.h.
for (const [fileType, label] of [
  [0, "VFT_UNKNOWN"], [1, "VFT_APP"], [2, "VFT_DLL"], [3, "VFT_DRV"],
  [4, "VFT_FONT"], [5, "VFT_VXD"], [7, "VFT_STATIC_LIB"]
] as const) {
  void test(`selects only ${label} for file type ${fileType}`, () => {
    const html = renderVersionPreview({ fixedFileInfo: { ...base, fileFlagsMask: 0, fileType,
      fileOS: 0xffffffff } });

    assert.equal(chipState(html, label), "sel");
    assert.equal(html.match(/class="opt sel"/g)?.length, 1);
    assert.doesNotMatch(html, /reserved/);
  });
}

void test("shows all OS and file type choices with exact code selection", () => {
  // VS_FIXEDFILEINFO: NT_WINDOWS32 = 0x40004; DRV = 3 is an enum, not APP | DLL.
  const html = renderVersionPreview({ fixedFileInfo: { ...base,
    fileFlagsMask: 0, fileOS: 0x40004, fileType: 3 } });

  assert.equal(chipState(html, "VOS_NT"), "sel");
  assert.equal(chipState(html, "VOS__WINDOWS32"), "sel");
  assert.equal(chipState(html, "VOS_UNKNOWN"), "dim");
  assert.equal(chipState(html, "VOS_DOS"), "dim");
  assert.equal(chipState(html, "VFT_DRV"), "sel");
  assert.equal(chipState(html, "VFT_APP"), "dim");
  assert.equal(chipState(html, "VFT_DLL"), "dim");
  assert.equal(chipState(html, "VFT_STATIC_LIB"), "dim");
  assert.match(html, /0x00040004/);
  assert.doesNotMatch(html, /&lt;span|&lt;div/);
});

void test("selects zero and composite OS codes without treating them as bit flags", () => {
  const zero = renderVersionPreview({ fixedFileInfo: { ...base, fileFlagsMask: 0 } });
  const os2 = renderVersionPreview({ fixedFileInfo: { ...base,
    fileFlagsMask: 0, fileOS: 0x30003, fileType: 7 } });
  const windows = renderVersionPreview({ fixedFileInfo: { ...base,
    fileFlagsMask: 0, fileOS: 4 } });

  assert.equal(chipState(zero, "VOS_UNKNOWN"), "sel");
  assert.equal(chipState(zero, "VFT_UNKNOWN"), "sel");
  assert.equal(chipState(zero, "VOS__BASE"), "sel");
  assert.equal(chipState(os2, "VOS_OS232"), "sel");
  assert.equal(chipState(os2, "VOS_DOS"), "dim");
  assert.equal(chipState(os2, "VOS_OS216"), "dim");
  assert.equal(chipState(os2, "VOS__PM32"), "sel");
  assert.equal(chipState(os2, "VOS__PM16"), "dim");
  assert.equal(chipState(os2, "VOS__WINDOWS16"), "dim");
  assert.equal(chipState(os2, "VFT_STATIC_LIB"), "sel");
  assert.equal(chipState(windows, "VOS_UNKNOWN"), "dim");
  assert.equal(chipState(windows, "VOS__WINDOWS32"), "sel");
});

void test("includes Windows CE and selects the base environment", () => {
  // Windows SDK verrsrc.h defines VOS_WINCE = 0x50000 and VOS__BASE = 0.
  const html = renderVersionPreview({ fixedFileInfo: { ...base,
    fileFlagsMask: 0, fileOS: 0x50000 } });

  assert.equal(chipState(html, "VOS_WINCE"), "sel");
  assert.equal(chipState(html, "VOS__BASE"), "sel");
  assert.equal(chipState(html, "VOS_NT"), "dim");
  assert.equal(chipState(html, "VOS_UNKNOWN"), "dim");
});

void test("preserves reserved values and escapes resource strings alongside chips", () => {
  const html = renderVersionPreview({ fileVersionString: "<script>bad</script>",
    fixedFileInfo: { ...base, fileFlagsMask: 0, fileOS: 0xffffffff, fileType: 99 } });

  assert.match(html, /0xffffffff/);
  assert.match(html, /0x00000063.*reserved/);
  assert.doesNotMatch(html, /class="opt sel"/);
  assert.match(html, /&lt;script>bad&lt;\/script>/);
});

void test("renders flags, mask, OS, type, subtype and full binary date", () => {
  const html = renderVersionPreview({ fixedFileInfo: { ...base,
    fileFlagsMask: 0x3f, fileFlags: 0x8000003f, fileOS: 0x40004,
    fileType: 3, fileSubtype: 4, fileDateMS: 0x12345678, fileDateLS: 0xabcdef01
  } });

  assert.match(html, /VS_FF_DEBUG.*VS_FF_PRERELEASE.*VS_FF_PATCHED.*VS_FF_PRIVATEBUILD/);
  assert.match(html, /VS_FF_INFOINFERRED.*VS_FF_SPECIALBUILD.*unknown 0x80000000/);
  assert.match(html, /VOS_NT.*VOS__WINDOWS32/s);
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
