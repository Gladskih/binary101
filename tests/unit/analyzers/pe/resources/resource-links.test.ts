import assert from "node:assert/strict";
import { test } from "node:test";
import { collectResourceLinks } from "../../../../../analyzers/pe/resources/resource-links.js";
import { createPreviewDetailGroup, createPreviewLangEntry } from
  "../../../../helpers/pe-resource-preview-fixture.js";
import { addDialogPreview } from "../../../../../analyzers/pe/resources/preview/dialog.js";
import { createInteractiveDialogResource, interactiveRibbonXml } from
  "../../../../fixtures/pe-resource-interactive-payloads.js";
import { addXmlResourcePreviewWithParser } from "../../../../../analyzers/pe/resources/preview/xml.js";
import { parseManifestTestXmlDocument } from "../../../../helpers/manifest-test-parser.js";

void test("links explicit dialog menu/image keys and reports absent or neutral targets", () => {
  const dialog = { ...createPreviewLangEntry(), ...addDialogPreview(createInteractiveDialogResource(), "DIALOG")?.preview };
  const references = collectResourceLinks([
    createPreviewDetailGroup("DIALOG", 401, dialog),
    createPreviewDetailGroup("MENU", 1, createPreviewLangEntry(0, 0, 0, 0))
  ]);

  assert.deepEqual(references.map(item => [item.relation, item.key, item.resolution.kind]), [
    ["Dialog menu", 1, "neutral"], ["Control #100 image", 1, "missing"]
  ]);
});

void test("preserves named hash keys and convention evidence", () => {
  const leaf = { ...createPreviewLangEntry(), ...addDialogPreview(createInteractiveDialogResource(), "DIALOG")?.preview };
  leaf.dialogPreview!.menu = "#1";
  const links = collectResourceLinks([
    createPreviewDetailGroup("DIALOG", 401, leaf),
    createPreviewDetailGroup("MENU", 1, createPreviewLangEntry()),
    createPreviewDetailGroup("TOOLBAR", 9, { ...createPreviewLangEntry(),
      toolbar: { version: 1, width: 16, height: 16, items: [] } })
  ]);

  assert.equal(links[0]?.resolution.kind, "missing");
  assert.equal(links.find(item => item.relation === "Toolbar image strip")?.evidence, "convention");
});

void test("collects Ribbon images and group variants while rejecting rounded XML IDs", () => {
  const xml = addXmlResourcePreviewWithParser(new TextEncoder().encode(interactiveRibbonXml),
    "RIBBON_XML", 65001, parseManifestTestXmlDocument);
  const invalid = addXmlResourcePreviewWithParser(new TextEncoder().encode(
    '<RIBBON_BAR><IMAGE><ID><VALUE>9007199254740993</VALUE></ID></IMAGE></RIBBON_BAR>'),
  "RIBBON_XML", 65001, parseManifestTestXmlDocument);
  const groups = [createPreviewDetailGroup("RIBBON_XML", 1, { ...createPreviewLangEntry(), ...xml?.preview }),
    createPreviewDetailGroup("RIBBON_XML", 2, { ...createPreviewLangEntry(), ...invalid?.preview })];
  const links = collectResourceLinks(groups);

  assert.ok(links.some(item => item.key === 1));
  assert.ok(links.every(item => item.key !== 9007199254740992));
  assert.ok(links.every(item => item.source.entry === 0));
});

void test("links group leaves and FONTDIR ordinals explicitly", () => {
  const image = {id:7,width:16,height:32,planes:1,bitCount:4,size:123};
  const links = collectResourceLinks([
    createPreviewDetailGroup("GROUP_CURSOR",1,{...createPreviewLangEntry(),imageGroup:{type:"CURSOR",entries:[image]}}),
    createPreviewDetailGroup("CURSOR",7,createPreviewLangEntry()),
    createPreviewDetailGroup("FONTDIR",1,{...createPreviewLangEntry(),fontDirectory:{entries:[
      {ordinal:9,font:{}}]}} as never),
    createPreviewDetailGroup("FONT",9,createPreviewLangEntry())
  ]);
  assert.deepEqual(links.map(item=>[item.relation,item.types,item.key,item.evidence,item.resolution.kind]),[
    ["Group image",["CURSOR"],7,"explicit","exact"],
    ["Font directory entry",["FONT"],9,"explicit","exact"]
  ]);
});

void test("resolves logical command strings and keeps MFC template conventions separate", () => {
  const links = collectResourceLinks([
    createPreviewDetailGroup("UIFILE",1,{...createPreviewLangEntry(),ribbonBml:{strings:[],commands:[
      {id:100,resources:[{kind:"Small image",resourceId:7},{kind:"Label",resourceId:42}]}]}}),
    createPreviewDetailGroup("BITMAP",7,createPreviewLangEntry()),
    createPreviewDetailGroup("STRING",3,{...createPreviewLangEntry(),stringTable:[{id:42,text:"Label"},
      {id:100,text:"Window\nDoc\nNew\nFilter\n.bin"}]}),
    createPreviewDetailGroup("MENU",100,createPreviewLangEntry())
  ]);
  assert.ok(links.some(item=>item.key===42 && item.targetKind==="string" && item.resolution.kind==="exact"));
  assert.ok(links.some(item=>item.key===7 && item.evidence==="explicit" && item.types[0]==="BITMAP"));
  assert.ok(links.some(item=>item.relation.includes("document template") && item.evidence==="convention"));
  assert.ok(links.some(item=>item.relation==="Command #100 string" && item.resolution.kind==="exact"));
});

void test("links event message IDs and matching dialogs without inventing absent command strings", () => {
  const links = collectResourceLinks([
    createPreviewDetailGroup("WEVT_TEMPLATE",1,{...createPreviewLangEntry(),wevtTemplate:{version:"3.1",providers:[
      {guid:"test",messageId:42,events:[],metadata:[],elements:[],templates:[],maps:[]}]}}),
    createPreviewDetailGroup("MESSAGETABLE",1,{...createPreviewLangEntry(),messageTable:{
      truncated:false,messages:[{id:42,strings:["Provider"]}]}}),
    createPreviewDetailGroup("DLGINIT",401,{...createPreviewLangEntry(),dialogInit:{entries:[]}}),
    createPreviewDetailGroup("DIALOG",401,createPreviewLangEntry())
  ]);
  assert.deepEqual(links.map(item=>[item.relation,item.key,item.targetKind,item.resolution.kind]),[
    ["Event message",42,"message","exact"],["Matching dialog",401,"resource","exact"]
  ]);
});

void test("collects named and high-DPI Ribbon image IDs", () => {
  const xml = addXmlResourcePreviewWithParser(new TextEncoder().encode(
    '<RIBBON_BAR><IMAGE_SMALL><ID><NAME>Main</NAME></ID><ID_HDPI><VALUE>9</VALUE></ID_HDPI>'+
    '<SIZE><VALUE>200</VALUE></SIZE></IMAGE_SMALL></RIBBON_BAR>'),"RIBBON_XML",65001,parseManifestTestXmlDocument);
  const links = collectResourceLinks([createPreviewDetailGroup("RIBBON_XML",1,
    {...createPreviewLangEntry(),...xml?.preview})]);
  assert.deepEqual(links.map(item=>[item.key,item.types,item.relation]),[
    ["Main",["BITMAP","PNG"],"Ribbon IMAGE_SMALL"],[9,["BITMAP","PNG"],"Ribbon IMAGE_SMALL (high DPI)"]
  ]);
});
