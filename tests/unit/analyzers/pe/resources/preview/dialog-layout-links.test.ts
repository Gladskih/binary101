import assert from "node:assert/strict";
import { test } from "node:test";
import { linkDialogLayouts } from "../../../../../../analyzers/pe/resources/preview/dialog-layout-links.js";
import type { ResourceDetailGroup,
  ResourceLangWithPreview } from "../../../../../../analyzers/pe/resources/preview/types.js";

const undecodedLanguage = (): ResourceLangWithPreview =>
  ({ lang: 1033 } as ResourceLangWithPreview);

const fixture = (): ResourceDetailGroup[] => [
  { typeName: "DIALOG", entries: [{ id: 101, name: null, langs: [
    { lang: 1033, dialogPreview: { templateKind: "standard", title: "Dialog", menu: null,
      className: null, x: 0, y: 0, width: 20, height: 20, style: 0, exStyle: 0, font: null,
      controls: [{ id: 12, kind: "BUTTON", title: "<OK>", x: 0, y: 0,
        width: 5, height: 5, style: 0, exStyle: 0 }] } }
  ] }] },
  { typeName: "AFX_DIALOG_LAYOUT", entries: [{ id: 101, name: null, langs: [
    { lang: 1033, dialogLayout: { version: 0, controls: [
      { moveX: 0, moveY: 0, sizeX: 100, sizeY: 0 },
      { moveX: 0, moveY: 0, sizeX: 0, sizeY: 0 }
    ] } },
    { lang: 1031, dialogLayout: { version: 0, controls: [
      { moveX: 10, moveY: 0, sizeX: 0, sizeY: 0 }
    ] } }
  ] }] }
] as ResourceDetailGroup[];

void test("links MFC layout rows to same-resource, same-language dialog controls", () => {
  const detail = fixture();
  const linked = linkDialogLayouts(detail);
  const controls = linked[1]?.entries[0]?.langs[0]?.dialogLayout?.controls;
  assert.deepEqual(controls?.[0]?.dialogControl,
    { id: 12, kind: "BUTTON", title: "<OK>" });
  assert.equal(controls?.[1]?.dialogControl, undefined);
  assert.equal(linked[1]?.entries[0]?.langs[1]?.dialogLayout?.controls[0]?.dialogControl,
    undefined);
  assert.strictEqual(linked[0], detail[0]);
});

void test("keeps unmatched resources and undecoded layouts unlinked", () => {
  const detail = fixture();
  detail[1]?.entries.push({ id: 102, name: null, langs: [
    { lang: 1033, dialogLayout: { version: 0, controls: [
      { moveX: 0, moveY: 0, sizeX: 0, sizeY: 0 }
    ] } }, { lang: 1033 }
  ] } as ResourceDetailGroup["entries"][number]);
  const linked = linkDialogLayouts(detail);
  assert.equal(linked[1]?.entries[1]?.langs[0]?.dialogLayout?.controls[0]?.dialogControl,
    undefined);
  assert.equal(linked[1]?.entries[1]?.langs[1]?.dialogLayout, undefined);
});

void test("matches named resources and rejects anonymous or missing dialogs", () => {
  const detail = fixture();
  const dialog = detail[0]?.entries[0];
  const layout = detail[1]?.entries[0];
  assert.ok(dialog && layout);
  dialog.id = null;
  dialog.name = "IDD_SAMPLE";
  layout.id = null;
  layout.name = "IDD_SAMPLE";
  assert.equal(linkDialogLayouts(detail)[1]?.entries[0]?.langs[0]?.dialogLayout?.controls[0]
    ?.dialogControl?.id, 12);
  layout.name = null;
  assert.equal(linkDialogLayouts(detail)[1]?.entries[0]?.langs[0]?.dialogLayout?.controls[0]
    ?.dialogControl, undefined);
  assert.equal(linkDialogLayouts(detail.slice(1))[0]?.entries[0]?.langs[0]?.dialogLayout
    ?.controls[0]?.dialogControl, undefined);
});

void test("does not attach an anonymous dialog or a different resource ID", () => {
  const detail = fixture();
  const dialog = detail[0]?.entries[0];
  const layout = detail[1]?.entries[0];
  assert.ok(dialog && layout);
  dialog.id = null;
  layout.id = null;
  assert.equal(linkDialogLayouts(detail)[1]?.entries[0]?.langs[0]?.dialogLayout?.controls[0]
    ?.dialogControl, undefined);
  dialog.id = 102;
  layout.id = 101;
  assert.equal(linkDialogLayouts(detail)[1]?.entries[0]?.langs[0]?.dialogLayout?.controls[0]
    ?.dialogControl, undefined);
});

void test("does not mistake an earlier resource group for DIALOG", () => {
  const detail = fixture();
  const unrelated: ResourceDetailGroup = { typeName: "MENU", entries: [
    { id: 101, name: null, langs: [undecodedLanguage()] }
  ] };
  const linked = linkDialogLayouts([unrelated, ...detail]);
  assert.equal(linked[2]?.entries[0]?.langs[0]?.dialogLayout?.controls[0]?.dialogControl?.id, 12);
});

void test("selects the matching dialog entry within its group", () => {
  const detail = fixture();
  detail[0]?.entries.unshift({ id: 101, name: "OTHER", langs: [undecodedLanguage()] });
  assert.equal(linkDialogLayouts(detail)[1]?.entries[0]?.langs[0]?.dialogLayout?.controls[0]
    ?.dialogControl?.id, 12);
});
