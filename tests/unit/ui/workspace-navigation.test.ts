import assert from "node:assert/strict";
import { test } from "node:test";
import { renderWorkspaceCards } from "../../../ui/workspace-navigation.js";
import { createBasePe } from "../../fixtures/pe-renderer-headers-fixture.js";
import { DOMParser } from "@xmldom/xmldom";

const readCards = (html: string) => Array.from(new DOMParser({ onError: assert.fail })
  .parseFromString(`<root>${html}</root>`, "application/xml").getElementsByTagName("article"));

void test("overview cards preserve section destinations, descriptions and supplemental origins", () => {
  const html = renderWorkspaceCards([
    { key: "analysis-<native>", title: "<Native>", description: "2 & 3", origin: undefined },
    { key: "analysis-derived", title: "Derived", description: "", origin: "supplemental" }
  ], null);

  assert.match(html, /data-workspace-target="analysis-&lt;native&gt;"/);
  assert.match(html, /&lt;Native&gt;/);
  assert.match(html, /2 &amp; 3/);
  assert.match(html, /data-analysis-origin="supplemental"/);
  const cards = readCards(html);
  assert.equal(cards.length, 2);
  assert.equal(cards[0]!.getAttribute("class"), "workspaceCard");
  assert.equal(cards[1]!.getAttribute("title"), "Supplemental analysis");
  assert.equal(cards[0]!.getElementsByTagName("h4")[0]!.firstChild!.nodeName, "button");
  assert.equal(cards[0]!.getElementsByTagName("button")[0]!.getAttribute("class"), "overviewLink");
  assert.equal(cards[0]!.getElementsByTagName("button")[0]!.getAttribute("type"), "button");
  assert.doesNotMatch(html, /<p><\/p>/);
  assert.equal(renderWorkspaceCards([], null), "");
});

void test("PE cards include recorded preview fields from the selected native destination", () => {
  const html = renderWorkspaceCards([{ key: "analysis-pe-headers", title: "PE/COFF headers",
    description: "", origin: undefined }], { analyzer: "pe", parsed: createBasePe() });

  assert.match(html, /COFF.Machine/);
  assert.match(html, /0x014c/);
  assert.match(html, /data-workspace-target="analysis-pe-headers"/);
});

void test("cards put format structures before supplemental analysis without duplicating DOS fields", () => {
  const sections = [
    { key: "analysis-derived", title: "Derived", description: "Analysis", origin: "supplemental" as const },
    { key: "analysis-dos-header", title: "DOS header", description: "e_lfanew repeated", origin: undefined },
    { key: "analysis-resources", title: "Resources", description: "Native summary", origin: undefined }
  ];
  const html = renderWorkspaceCards(sections, { analyzer: "pe", parsed: createBasePe() });

  assert.deepEqual(readCards(html).map(card => card.getElementsByTagName("button")[0]!
    .getAttribute("data-workspace-target")), ["analysis-dos-header", "analysis-resources", "analysis-derived"]);
  assert.doesNotMatch(html, /e_lfanew repeated/);
  assert.match(html, /Native summary/);
  assert.match(renderWorkspaceCards(sections, null), /e_lfanew repeated/);
  assert.doesNotMatch(renderWorkspaceCards(sections, { analyzer: null, parsed: null }), /<dl/);
});

void test("preview destinations must match the complete source identifier", () => {
  const html = renderWorkspaceCards([{ key: "copy-analysis-pe-headers", title: "Copy",
    description: "", origin: undefined }], { analyzer: "pe", parsed: createBasePe() });

  assert.doesNotMatch(html, /COFF.Machine/);
});
