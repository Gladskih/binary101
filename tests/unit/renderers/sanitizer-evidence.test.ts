import assert from "node:assert/strict";
import { test } from "node:test";
import { DOMParser } from "@xmldom/xmldom";
import { renderSanitizerEvidence } from "../../../renderers/sanitizer-evidence.js";

void test("shows absence as inconclusive", () => {
  const html = renderSanitizerEvidence([]);
  assert.match(html, /No supported sanitizer evidence/);
  assert.match(html, /trap-only/);
  assert.match(html, /does not establish absence of sanitizers/);
  assert.doesNotMatch(html, /<table/);
});

void test("renders a semantic table and distinguishes runtime presence from execution", () => {
  const html = renderSanitizerEvidence([
    { tool: "ASan", kind: "dependency", source: "ELF DT_NEEDED", name: "libasan.so.8" },
    { tool: "ASan", kind: "reference", source: "ELF symbols", name: "__asan_init" },
    { tool: "LSan", kind: "definition", source: "ELF symbols", name: "__lsan_init" },
    { tool: "Go race detector", kind: "build-setting", source: "Go build information", name: "-race=true" }
  ]);
  assert.match(html, /<thead><tr><th scope="col">Tool/);
  assert.match(html, /Runtime dependency/);
  assert.match(html, /ABI reference/);
  assert.match(html, /Runtime ABI definition/);
  assert.match(html, /Recorded build setting/);
  assert.match(html, /does not prove/);
  assert.match(html, /A runtime dependency or ABI definition/);
  assert.match(html, /Bundled runtimes may expose several sanitizers/);
  assert.match(html, /during execution/);
  assert.doesNotMatch(html, /coverage instrumentation/);
});

void test("escapes evidence and source text", () => {
  const html = renderSanitizerEvidence([{ tool: "ASan", kind: "reference",
    source: "<script>unsafe</script>", name: "<img src=x onerror=alert(1)>" }]);
  assert.doesNotMatch(html, /<script>|<img/);
  assert.match(html, /&lt;script>/);
  assert.match(html, /&lt;img/);
});

void test("explains that coverage instrumentation is not an error detector", () => {
  const html = renderSanitizerEvidence([
    { tool: "SanitizerCoverage", kind: "reference", source: "ELF symbols",
      name: "__sanitizer_cov_trace_pc_guard" },
    { tool: "ASan", kind: "dependency", source: "ELF DT_NEEDED", name: "libasan.so.8" }
  ]);
  assert.match(html, /coverage instrumentation/);
  assert.match(html, /not itself an error detector/);
});

void test("produces valid table structure with all evidence fields in separate cells", () => {
  const html = renderSanitizerEvidence([
    { tool: "ASan", kind: "reference", source: "ELF symbols", name: "__asan_init" },
    { tool: "ASan", kind: "reference", source: "ELF symbols", name: "__asan_report_load4" }
  ]);
  const errors: string[] = [];
  const document = new DOMParser({ onError: (_level, message) => { errors.push(message); } })
    .parseFromString(`<main>${html}</main>`, "text/html");
  assert.deepEqual(errors, []);
  assert.equal(document.getElementsByTagName("div")[0]!.getAttribute("class"), "tableWrap");
  const table = document.getElementsByTagName("table")[0]!;
  assert.equal(table.getElementsByTagName("thead").length, 1);
  assert.deepEqual(Array.from(table.getElementsByTagName("th")).map(cell => cell.textContent),
    ["Tool", "Evidence kind", "Source", "Name / setting"]);
  assert.deepEqual(Array.from(table.getElementsByTagName("th")).map(cell =>
    cell.getAttribute("scope")), ["col", "col", "col", "col"]);
  const body = table.getElementsByTagName("tbody")[0]!;
  assert.equal(body.childNodes.length, 2); // No stray text or elements between rows.
  assert.deepEqual(Array.from(body.getElementsByTagName("tr")).map(row =>
    Array.from(row.getElementsByTagName("td")).map(cell => cell.textContent)), [
    ["ASan", "ABI reference", "ELF symbols", "__asan_init"],
    ["ASan", "ABI reference", "ELF symbols", "__asan_report_load4"]
  ]);
});
