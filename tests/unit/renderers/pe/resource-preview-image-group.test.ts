import assert from "node:assert/strict";
import { test } from "node:test";
import { renderImageGroupPreview } from "../../../../renderers/pe/resource-preview-image-group.js";
import { indexResourceLeaves } from "../../../../analyzers/pe/resources/resource-index.js";
import { linkedDialogPreview } from "../../../helpers/pe-resource-linked-preview.js";

void test("renders every variant, links its leaf and reports missing images", () => {
  const context = linkedDialogPreview();
  context.catalog.detail[2]!.typeName = "ICON";
  context.catalog = indexResourceLeaves(context.catalog.detail);
  const image = {id:1,width:32,height:32,planes:1,bitCount:32,size:10};
  const html = renderImageGroupPreview({type:"ICON",entries:[image,{...image,id:999}]},context);

  assert.match(html,/32/);
  assert.match(html,/Not present in this file/);
  assert.match(html,/data-pe-resource-target/);
});
