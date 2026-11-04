import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDialogPreview } from "../../../../renderers/pe/resource-preview-dialog.js";
import { linkedDialogPreview } from "../../../helpers/pe-resource-linked-preview.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

void test("renders an empty dialog without inventing a font, menu or controls", () => {
  const source = expectDefined(linkedDialogPreview().catalog.detail[0]?.entries[0]?.langs[0]?.dialogPreview);
  const html = renderDialogPreview({...source,title:null,menu:null,className:null,font:null,controls:[],helpId:null});

  assert.match(html,/untitled dialog/);
  assert.match(html,/0 controls/);
  assert.doesNotMatch(html,/peDialog__menu/);
  assert.match(html,/sans-serif/);
});

void test("renders extended font metadata and preserves literal named menu identities", () => {
  const context = linkedDialogPreview();
  const source = expectDefined(context.catalog.detail[0]?.entries[0]?.langs[0]?.dialogPreview);
  const html = renderDialogPreview({...source,menu:"#1",className:"Custom",templateKind:"extended",helpId:7,
    exStyle:0x400000,font:{pointSize:10,typeface:'Test "font"',weight:700,italic:true,charset:1}},context);

  assert.match(html,/DLGTEMPLATEEX/);
  assert.match(html,/Class: Custom/);
  assert.match(html,/Help ID: 7/);
  assert.match(html,/weight 700, italic/);
  assert.match(html,/dir="rtl"/);
  assert.doesNotMatch(html,/peDialog__menu/);
});
