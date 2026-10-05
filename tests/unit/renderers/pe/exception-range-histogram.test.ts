"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { DOMParser } from "@xmldom/xmldom";
import { createEmptyExceptionDirectory } from "../../../../analyzers/pe/exception/types.js";
import { renderExceptionRangeHistogram } from "../../../../renderers/pe/exception-range-histogram.js";
import { parsePe, isPeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import { createPePdataRangeFile } from "../../../fixtures/pe-pdata-range-file.js";

const renderLengths = (lengths: number[], functionCount = lengths.length): string =>
  renderExceptionRangeHistogram({
    ...createEmptyExceptionDirectory([]), rangeLengths: lengths, functionCount
  });

const parsePlot = (html: string) => {
  const svg = html.match(/<svg\b[\s\S]*?<\/svg>/)?.[0];
  assert.ok(svg, "Expected an SVG histogram");
  return new DOMParser().parseFromString(svg, "image/svg+xml");
};

const barTitles = (html: string): string[] =>
  Array.from(parsePlot(html).getElementsByTagName("title"), node => node.textContent ?? "");

void test("histogram groups inclusive byte intervals and keeps empty interior bins", () => {
  // Power-of-two bin boundaries: 1; 2–3; 4–7; 8–15, including both edges.
  const html = renderLengths([1, 2, 3, 8, 15]);

  assert.deepEqual(barTitles(html), [
    "1 bytes: 1 ranges", "2–3 bytes: 2 ranges", "4–7 bytes: 0 ranges", "8–15 bytes: 2 ranges"
  ]);
  assert.match(html, /5 measured ranges/);
  assert.doesNotMatch(html, /entries excluded/);
  assert.doesNotMatch(html, /hover for exact byte intervals/);
  assert.deepEqual(Array.from(parsePlot(html).getElementsByTagName("text"))
    .filter(node => node.getAttribute("class") === "rangeHistogram__tick")
    .slice(5).map(node => node.textContent), ["1", "2", "4", "8"]);
  assert.match(html, /<figure class="rangeHistogram"><figcaption class="rangeHistogram__caption">/);
  assert.match(html, /<strong>Range length distribution<\/strong><span>5 measured ranges<\/span>/);
  assert.match(html, /<div class="rangeHistogram__scroll"><svg/);
  assert.match(html, /Labels mark lower bounds\. Each entry counts once\./);
  assert.match(html, /Ranges may cover part of a function; functions without .pdata entries are absent\./);
});

void test("histogram distinguishes each neighboring power-of-two interval", () => {
  const html = renderLengths([4, 7, 8, 16, 31, 32]);

  assert.deepEqual(barTitles(html), [
    "4–7 bytes: 2 ranges", "8–15 bytes: 1 ranges",
    "16–31 bytes: 2 ranges", "32–63 bytes: 1 ranges"
  ]);
});

void test("histogram states when a format provides no lengths", () => {
  const html = renderExceptionRangeHistogram(createEmptyExceptionDirectory([], "ready-to-run-x86"));

  assert.match(html, /Range length distribution is unavailable/);
  assert.doesNotMatch(html, /<svg/);
});

void test("histogram states when the validated length collection is empty", () => {
  const html = renderLengths([]);

  assert.match(html, /no validated ranges with known lengths/);
  assert.doesNotMatch(html, /<svg/);
});

void test("histogram visibly excludes invalid, nonfinite and out-of-range lengths", () => {
  // PE RUNTIME_FUNCTION RVAs are unsigned 32-bit image offsets.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-runtime_function
  const html = renderLengths([1, 0, -1, 1.5, NaN, Infinity, -Infinity, 2 ** 32]);

  assert.deepEqual(barTitles(html), ["1 bytes: 1 ranges"]);
  assert.match(html, /1 measured ranges · 7 entries excluded/);
  assert.doesNotMatch(html, /NaN|Infinity/);
});

void test("histogram reports a nonempty collection with no usable lengths", () => {
  const html = renderLengths([0, -1, NaN]);

  assert.match(html, /No valid range lengths to plot/);
  assert.doesNotMatch(html, /<svg/);
});

void test("histogram counts missing lengths without pretending they are zero-byte ranges", () => {
  const html = renderLengths([8], 3);

  assert.deepEqual(barTitles(html), ["8–15 bytes: 1 ranges"]);
  assert.match(html, /1 measured ranges · 2 entries excluded \(invalid or unknown length\)/);
});

void test("histogram does not show negative excluded counts for inconsistent totals", () => {
  const html = renderLengths([8], 0);

  assert.match(html, /1 measured ranges/);
  assert.doesNotMatch(html, /entries excluded/);
});

void test("histogram displays binary units with exact byte intervals in the description", () => {
  // IEC binary prefixes denote powers of 1024, independently of parser constants.
  const html = renderLengths([1024, 1024 ** 2, 1024 ** 3]);
  const plot = parsePlot(html);

  assert.match(plot.getElementsByTagName("desc")[0]?.textContent ?? "", /1,024–2,047 bytes: 1 ranges/);
  assert.match(html, />1 KiB<.*>1 MiB<.*>1 GiB</);
  assert.match(html, /role="img" aria-label="Histogram of code range lengths/);
  assert.equal(plot.getElementsByTagName("desc")[0]?.textContent,
    barTitles(html).join("; "));
  assert.ok(plot.documentElement);
  assert.equal(plot.documentElement.getAttribute("viewBox"), "0 0 1046 280");
  assert.deepEqual(Array.from(plot.documentElement.childNodes)
    .filter(node => node.nodeType === 3), []);
});

void test("histogram bounds the chart to 32 bins for the largest PE range", () => {
  // A 32-bit RVA range cannot have a byte length beyond UINT32_MAX.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-runtime_function
  const html = renderLengths([1, 0xffffffff]);
  const plot = parsePlot(html);

  assert.equal(plot.getElementsByTagName("rect").length, 32);
  assert.equal(barTitles(html).at(-1), "2,147,483,648–4,294,967,295 bytes: 1 ranges");
  assert.match(html, />2 GiB</);
  assert.equal(plot.documentElement?.getAttribute("viewBox"), "0 0 1552 280");
  assert.equal(plot.documentElement?.getAttribute("style"), "min-width:1432px");
});

void test("histogram has integer axis ticks and finite geometry for one range", () => {
  const plot = parsePlot(renderLengths([8]));

  assert.equal(plot.documentElement?.getAttribute("viewBox"), "0 0 640 280");
  assert.deepEqual(Array.from(plot.getElementsByTagName("text")).slice(1, 6)
    .map(node => node.textContent), ["0", "1", "2", "3", "4"]);
  assert.equal(plot.getElementsByTagName("rect")[0]?.getAttribute("height"), "40");
  assert.equal(plot.documentElement?.getAttribute("style"), "min-width:640px");
  assert.equal(plot.getElementsByTagName("text")[0]?.getAttribute("x"), "40");
  assert.equal(plot.getElementsByTagName("text")[0]?.textContent, "Number of ranges");
});

void test("histogram scales bar heights to observed counts with integer ticks", () => {
  const html = renderLengths([2, 2, 2, 2, 2, 2, 2, 2, 4]);
  const plot = parsePlot(html);

  assert.deepEqual(Array.from(plot.getElementsByTagName("rect"))
    .map(node => node.getAttribute("height")), ["160", "20"]);
  assert.deepEqual(Array.from(plot.getElementsByTagName("text")).slice(1, 6)
    .map(node => node.textContent), ["0", "2", "4", "6", "8"]);
  // Reviewed layout: bars rise from a common baseline to the count-axis grid lines.
  assert.deepEqual(Array.from(plot.getElementsByTagName("path"))
    .map(node => node.getAttribute("d")), [
    "M40 214H620", "M40 174H620", "M40 134H620", "M40 94H620", "M40 54H620"
  ]);
  assert.deepEqual(Array.from(plot.getElementsByTagName("rect"))
    .map(node => node.getAttribute("y")), ["54", "194"]);
  const ticks = Array.from(plot.getElementsByTagName("text"))
    .filter(node => node.getAttribute("class") === "rangeHistogram__tick");
  assert.equal(ticks[0]?.getAttribute("x"), "30");
  assert.equal(ticks[0]?.getAttribute("y"), "218");
  const counts = Array.from(plot.getElementsByTagName("text"))
    .filter(node => node.getAttribute("class") === "rangeHistogram__count");
  assert.equal(counts[0]?.getAttribute("x"), ticks[5]?.getAttribute("x"));
  assert.equal(counts[1]?.getAttribute("x"), ticks[6]?.getAttribute("x"));
  assert.equal(counts[0]?.getAttribute("y"), "46");
  // Both bins occupy equal horizontal space; labels are centered over their bars.
  assert.deepEqual(Array.from(plot.getElementsByTagName("rect"))
    .map(node => node.getAttribute("x")), ["166", "446"]);
  assert.deepEqual(counts.map(node => node.getAttribute("x")), ["180", "460"]);
  assert.deepEqual(ticks.slice(5).map(node => node.getAttribute("x")), ["180", "460"]);
  assert.equal(plot.getElementsByTagName("text").item(10)?.getAttribute("x"), "620");
});

void test("histogram retains room for long count labels", () => {
  const html = renderLengths(Array<number>(10000).fill(2));

  assert.match(html, /10,000 measured ranges/);
  assert.match(html, /text-anchor="end">10,000<\/text>/);
  // Long count labels need more room than the compact 40px margin.
  assert.equal(parsePlot(html).getElementsByTagName("text")[0]?.getAttribute("x"), "52");
});

void test("histogram renders lengths parsed from the browser's complete PE sample", async () => {
  const parsed = await parsePe(createPePdataRangeFile() as unknown as File);

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.ok(parsed.exception);
  assert.deepEqual(parsed.exception.rangeLengths, [1, 2, 3, 8, 16]);
  assert.deepEqual(barTitles(renderExceptionRangeHistogram(parsed.exception)), [
    "1 bytes: 1 ranges", "2–3 bytes: 2 ranges", "4–7 bytes: 0 ranges",
    "8–15 bytes: 1 ranges", "16–31 bytes: 1 ranges"
  ]);
});
