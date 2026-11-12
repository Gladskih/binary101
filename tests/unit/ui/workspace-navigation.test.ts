import assert from "node:assert/strict";
import { test } from "node:test";
import { renderWorkspaceCards } from "../../../ui/workspace-navigation.js";
import { createBasePe } from "../../fixtures/pe-renderer-headers-fixture.js";
import { readOverviewDocument, readOverviewFacts } from "../../helpers/overview-card-fixture.js";

void test("workspace cards are native tile buttons containing source highlights", () => {
  const html = renderWorkspaceCards([{ key: "analysis-pe-headers", title: "<Native>",
    description: "Counts alone", origin: undefined }], { analyzer: "pe", parsed: createBasePe() });
  const buttons = readOverviewDocument(html).getElementsByTagName("button");

  assert.equal(buttons.length, 1);
  assert.equal(buttons[0]!.getAttribute("class"), "workspaceCard");
  assert.equal(buttons[0]!.getAttribute("type"), "button");
  assert.equal(buttons[0]!.getAttribute("data-workspace-target"), "analysis-pe-headers");
  assert.match(html, /&lt;Native&gt;/);
  assert.equal(readOverviewFacts(html)[0]![1], "x86 (I386)");
  assert.doesNotMatch(html, /Counts alone|0x014c|<article|<table|<dl/);
});

void test("format structures precede supplemental tiles and empty destinations are omitted", () => {
  const pe = createBasePe();
  const html = renderWorkspaceCards([
    { key: "analysis-pe-headers", title: "Analysis", description: "", origin: "supplemental" },
    { key: "analysis-dos-header", title: "DOS", description: "MZ", origin: undefined },
    { key: "analysis-pe-headers", title: "Native", description: "", origin: undefined }
  ], { analyzer: "pe", parsed: pe });
  const buttons = Array.from(readOverviewDocument(html).getElementsByTagName("button"));

  assert.equal(buttons.length, 2);
  assert.match(buttons[0]!.textContent!, /Native/);
  assert.match(buttons[1]!.textContent!, /Analysis/);
  assert.equal(buttons[1]!.getAttribute("data-analysis-origin"), "supplemental");
  assert.doesNotMatch(html, />DOS</);
});

void test("missing results, unknown formats and unmatched destinations produce no empty tiles", () => {
  const sections = [{ key: "copy-analysis-pe-headers", title: "Copy", description: "", origin: undefined }];

  assert.equal(renderWorkspaceCards([], null), "");
  assert.equal(renderWorkspaceCards(sections, null), "");
  assert.equal(renderWorkspaceCards(sections, { analyzer: null, parsed: null }), "");
  assert.equal(renderWorkspaceCards(sections, { analyzer: "pe", parsed: createBasePe() }), "");
});
