import assert from "node:assert/strict";
import { test } from "node:test";
import { overviewFact, renderOverviewCard } from "../../../renderers/overview-card.js";
import { readOverviewDocument, readOverviewFacts } from "../../helpers/overview-card-fixture.js";

void test("a card is one native button with a labelled description and phrasing content", () => {
  const html = renderOverviewCard("<Imports>", "analysis-imports", overviewFact("DLL", "A&B.dll"));
  const document = readOverviewDocument(html);
  const button = document.getElementsByTagName("button")[0]!;
  const spans = Array.from(document.getElementsByTagName("span"));

  assert.equal(document.getElementsByTagName("button").length, 1);
  assert.equal(button.getAttribute("type"), "button");
  assert.equal(button.getAttribute("data-workspace-target"), "analysis-imports");
  assert.ok(button.getAttribute("aria-labelledby"));
  assert.ok(button.getAttribute("aria-describedby"));
  assert.equal(spans.find(span => span.getAttribute("id") === button.getAttribute("aria-labelledby"))!
    .textContent, "<Imports>");
  assert.ok(spans.some(span => span.getAttribute("id") === button.getAttribute("aria-describedby")));
  assert.deepEqual(readOverviewFacts(html), [["DLL", "A&B.dll"]]);
  assert.doesNotMatch(html, /<table|<ul|<ol|<a |tabindex|<details|<h[1-6]/);
  assert.equal(button.hasAttribute("data-analysis-origin"), false);
});

void test("different tile targets have distinct accessible name and description IDs", () => {
  const cards = readOverviewDocument(renderOverviewCard("One", "one", overviewFact("Value", "1")) +
    renderOverviewCard("Two", "two", overviewFact("Value", "2"))).getElementsByTagName("button");

  assert.notEqual(cards[0]!.getAttribute("aria-labelledby"), cards[1]!.getAttribute("aria-labelledby"));
  assert.notEqual(cards[0]!.getAttribute("aria-describedby"), cards[1]!.getAttribute("aria-describedby"));
});

void test("empty highlights omit a card while supplemental origin is explicit", () => {
  assert.equal(renderOverviewCard("Empty", "analysis-empty", ""), "");
  const html = renderOverviewCard("Check", "analysis-check", overviewFact("Count", "0"), "supplemental");

  assert.equal(readOverviewDocument(html).getElementsByTagName("button")[0]!
    .getAttribute("data-analysis-origin"), "supplemental");
  assert.deepEqual(readOverviewFacts(html), [["Count", "0"]]);
});

void test("untrusted labels, values and navigation targets cannot add markup", () => {
  const html = renderOverviewCard("<script>", 'a" data-bad="yes', overviewFact('"<label>', "<img>&"));
  const document = readOverviewDocument(html);

  assert.equal(document.getElementsByTagName("img").length, 0);
  assert.equal(document.getElementsByTagName("script").length, 0);
  assert.equal(document.getElementsByTagName("button")[0]!.hasAttribute("data-bad"), false);
  assert.deepEqual(readOverviewFacts(html), [['"<label>', "<img>&"]]);
});
