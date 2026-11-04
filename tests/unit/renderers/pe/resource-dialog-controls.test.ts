import assert from "node:assert/strict";
import { test } from "node:test";
import { linkedDialogPreview } from "../../../helpers/pe-resource-linked-preview.js";
import { renderDialogControl } from "../../../../renderers/pe/resource-dialog-controls.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

void test("preserves DLU bounds and applies linked initialization/layout values", () => {
  const context = linkedDialogPreview();
  const dialog = expectDefined(context.catalog.detail[0]?.entries[0]?.langs[0]?.dialogPreview);
  const html = renderDialogControl(dialog.controls[2]!,2,context,3,"rtl");

  assert.match(html, /right:var\(--pe-control-x\)/);
  assert.match(html, /36 \* var\(--pe-dlu-x\)/);
  assert.match(html, /var\(--pe-dialog-dx\) \* 1/);
  assert.match(html, /var\(--pe-dialog-dy\) \* 0.5/);
  assert.match(html, /&lt;First/);
  assert.match(html, /data-pe-dialog-tab-index="3"/);
});

void test("escapes captions, renders system controls and keeps custom classes visible", () => {
  const context = linkedDialogPreview();
  const dialog = expectDefined(context.catalog.detail[0]?.entries[0]?.langs[0]?.dialogPreview);
  const control = dialog.controls[1]!;

  assert.match(renderDialogControl(control,1), /<u>R<\/u>emember/);
  assert.match(renderDialogControl({...control,title:"<img>",kind:"Unknown"},0), /&lt;img/);
  assert.match(renderDialogControl({...control,kind:"EDIT",style:0x20},0), /peDialog__control--input/);
  assert.match(renderDialogControl({...control,kind:"STATIC",style:0x10},0), /peDialog__control--line/);
});

void test("describes button styles, static text, image links and empty initialization safely", () => {
  const context = linkedDialogPreview();
  const dialog = expectDefined(context.catalog.detail[0]?.entries[0]?.langs[0]?.dialogPreview);
  const control = dialog.controls[1]!;

  assert.match(renderDialogControl({...control,style:7},0),/groupLabel/);
  assert.match(renderDialogControl({...control,style:4},0),/aria-hidden/);
  assert.match(renderDialogControl({...control,style:0x8000001},0),/defaultButton.*disabled/su);
  assert.match(renderDialogControl({...control,kind:"STATIC",style:14,title:1},0,context),/data:image/);
  assert.match(renderDialogControl({...control,kind:"STATIC",style:3,title:null},0,context),/data-pe-dialog-control/);
  assert.match(renderDialogControl({...control,kind:"STATIC",style:0x80,title:"&Plain"},0),/&amp;Plain/);
  assert.match(renderDialogControl({...control,kind:"LISTBOX",id:999},0,context),/control--input/);
  assert.match(renderDialogControl({...control,kind:"COMBOBOX",id:999},0),/peDialog__arrow/);
  assert.match(renderDialogControl({...control,kind:"EDIT",style:4},0),/white-space:normal/);
  assert.match(renderDialogControl({...control,kind:"MSCTLS_PROGRESS32"},0),/peDialog__progress/);
  assert.match(renderDialogControl({...control,kind:"MSCTLS_TRACKBAR32"},0),/peDialog__track/);
  assert.match(renderDialogControl({...control,kind:"SCROLLBAR"},0),/control--custom/);
});
