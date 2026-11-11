import assert from "node:assert/strict";
import { test } from "node:test";
import { linkedDialogPreview } from "../../../helpers/pe-resource-linked-preview.js";
import { resourceAt } from "../../../../analyzers/pe/resources/resource-index.js";
import { getResourcePreviewModel, renderResourceConnections, resolvedPreview,
  resolvedResourceImage, resourceNavigationLink, resourceLocationLabel } from
  "../../../../renderers/pe/resource-preview-context.js";

void test("indexes forward/back references once and resolves only confirmed language variants", () => {
  const context = linkedDialogPreview();
  const resources = {top:[],detail:context.catalog.detail};
  const model = getResourcePreviewModel(resources);
  const image = resolvedResourceImage(context,["BITMAP"],1);

  assert.strictEqual(getResourcePreviewModel(resources),model);
  assert.equal(image,"data:image/png;base64,AQ==");
  assert.equal(resolvedPreview(undefined,["MENU"],1),undefined);
  assert.equal(resolvedPreview(context,["MENU"],"1"),undefined);
  assert.match(renderResourceConnections({...model,source:context.source}), /Dialog menu/);
  assert.match(renderResourceConnections({...model,source:{group:1,entry:0,language:0}}), /Used by/);
  assert.equal(renderResourceConnections({...model,source:{group:2,entry:0,language:0}}),"");
  assert.match(renderResourceConnections({...model,source:{group:1,entry:0,language:0}}),
    /^<section class="peResourceConnections"><h5 class="collectionSummary">Resource references/);
});

void test("escapes resource labels and preserves navigation coordinates", () => {
  const context = linkedDialogPreview();
  context.catalog.detail[1]!.entries[0]!.name = "<Menu>";
  const target = {group:1,entry:0,language:0};

  assert.match(resourceNavigationLink(context.catalog,target), /&lt;Menu/);
  assert.match(resourceNavigationLink(context.catalog,target), /data-pe-resource-target="1-0-0"/);
  assert.match(resourceLocationLabel(context.catalog,{group:-1,entry:0,language:0}), /unavailable/);
  assert.equal(resourceAt(context.catalog,{group:99,entry:0,language:0}),undefined);
});

void test("renders unconfirmed outgoing links and missing images without picking a target", () => {
  const context = linkedDialogPreview();
  context.catalog.detail[1]!.entries[0]!.langs[0]!.lang=1041;
  const model = getResourcePreviewModel({top:[],detail:context.catalog.detail});
  const html = renderResourceConnections({...model,source:context.source});

  assert.equal(resolvedPreview(context,["MENU"],1),undefined);
  assert.equal(resolvedResourceImage(undefined,["ICON"],1),undefined);
  assert.equal(resolvedResourceImage(context,["ICON"],99),undefined);
  assert.match(html,/candidate/);
  assert.match(renderResourceConnections(context),/Resource references/);
  assert.match(renderResourceConnections({...context,source:{group:1,entry:0,language:0}}),/Used by/);
});
