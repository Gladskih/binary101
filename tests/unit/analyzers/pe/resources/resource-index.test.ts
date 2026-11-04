import assert from "node:assert/strict";
import { test } from "node:test";
import { indexResourceLeaves, resolveResourceReference, resolveResourceAlternatives,
  resolveResourceContent, resourceAt } from
  "../../../../../analyzers/pe/resources/resource-index.js";
import { createPreviewDetailGroup, createPreviewLangEntry } from
  "../../../../helpers/pe-resource-preview-fixture.js";

void test("resolves exact and neutral languages without choosing an arbitrary candidate", () => {
  const group = createPreviewDetailGroup("BITMAP", 7, createPreviewLangEntry(1, 1, 0, 1041));
  group.entries[0]!.langs.push(createPreviewLangEntry(2, 1, 0, 0));
  const catalog = indexResourceLeaves([group]);

  assert.equal(resolveResourceReference(catalog, "BITMAP", 7, 1041).kind, "exact");
  const resolution = resolveResourceReference(catalog, "BITMAP", 7, 1033);
  assert.equal(resolution.kind, "neutral");
  assert.equal(resourceAt(catalog, resolution.targets[0]!)?.lang, 0);
  assert.equal(resolveResourceReference(catalog, "BITMAP", "7", 1033).kind, "missing");
});

void test("retains ambiguity and absent targets", () => {
  const group = createPreviewDetailGroup("MENU", 7, createPreviewLangEntry(1, 1));
  group.entries[0]!.langs.push(createPreviewLangEntry(2, 1));
  const catalog = indexResourceLeaves([group]);

  assert.equal(resolveResourceReference(catalog, "MENU", 7, 1033).kind, "ambiguous");
  assert.deepEqual(resolveResourceReference(catalog, "MENU", 8, null), { kind: "missing", targets: [] });
  assert.equal(resourceAt(catalog, { group: -1, entry: 0, language: 0 }), undefined);
});

void test("exposes other languages as candidates rather than a confirmed match", () => {
  const catalog = indexResourceLeaves([
    createPreviewDetailGroup("ICON", 7, createPreviewLangEntry(1, 1, 0, 1041))
  ]);

  assert.equal(resolveResourceReference(catalog, "ICON", 7, 1033).kind, "candidate");
});

void test("does not guess between resource types sharing the same ID", () => {
  const catalog = indexResourceLeaves([
    createPreviewDetailGroup("BITMAP",1,createPreviewLangEntry()),
    createPreviewDetailGroup("PNG",1,createPreviewLangEntry())
  ]);
  const targets = resolveResourceAlternatives(catalog,["BITMAP","PNG"],1,1033);

  assert.equal(targets.kind,"ambiguous");
  assert.equal(targets.targets.length,2);
});

void test("indexes logical STRING/MESSAGETABLE content and preserves null neutrality and duplicate IDs", () => {
  const catalog = indexResourceLeaves([
    createPreviewDetailGroup("STRING",1,{...createPreviewLangEntry(0,0,0,null),
      stringTable:[{id:7,text:"Seven"},{id:null,text:"Unnamed"}]}),
    createPreviewDetailGroup("MESSAGETABLE",1,{...createPreviewLangEntry(),
      messageTable:{messages:[{id:42,strings:["Answer"]}],truncated:false}})
  ]);
  assert.equal(resolveResourceContent(catalog,"STRING",7,1033).kind,"neutral");
  assert.equal(resolveResourceContent(catalog,"MESSAGETABLE",42,1033).kind,"exact");
  assert.equal(resolveResourceContent(catalog,"MESSAGETABLE",7,1033).kind,"missing");
  assert.equal(resolveResourceReference(catalog,"STRING",1,1041).kind,"neutral");
});

void test("retains ambiguity between multiple neutral variants", () => {
  const group = createPreviewDetailGroup("ICON",7,createPreviewLangEntry(0,0,0,0));
  group.entries[0]!.langs.push(createPreviewLangEntry(0,0,0,null));
  const resolution = resolveResourceReference(indexResourceLeaves([group]),"ICON",7,1033);
  assert.equal(resolution.kind,"ambiguous");
  assert.equal(resolution.targets.length,2);
});
