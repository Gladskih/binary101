import assert from "node:assert/strict";
import { test } from "node:test";
import { renderNtRiscStatistics } from "../../../../renderers/pe/exception-nt-risc.js";
import { createEmptyExceptionDirectory } from "../../../../analyzers/pe/exception/types.js";

void test("NT RISC statistics retain prolog summaries and show nonempty numeric exception modes", () => {
  const out: string[] = [];
  renderNtRiscStatistics({ ...createEmptyExceptionDirectory([], "nt-risc32"), beginRvas: [1, 2, 3],
    riscPrologs: { count: 2, empty: 1, minimumBytes: 0, maximumBytes: 16 },
    riscExceptionModes: [2, 0, 0, 0, 0, 0, 0, 1] }, out);
  const html = out.join("");
  assert.match(html, /Ranges with unresolved inline metadata<\/dt><dd>1<\/dd>/);
  assert.match(html, /Prologs with resolved boundaries<\/dt><dd>2<\/dd>/);
  assert.match(html, /Empty prologs<\/dt><dd>1<\/dd>/);
  assert.match(html, /Shortest prolog \(bytes\)<\/dt><dd>0<\/dd>/);
  assert.match(html, /Longest prolog \(bytes\)<\/dt><dd>16<\/dd>/);
  assert.match(html, /Exception mode 0<\/dt><dd>2<\/dd>/);
  assert.match(html, /Exception mode 7<\/dt><dd>1<\/dd>/);
  assert.match(html, /Named meanings are not established for every ABI/);
  assert.doesNotMatch(html, /Exception mode 1|<table|0x/);
});

void test("Alpha secondary ranges have their own summary without being called unresolved inline metadata", () => {
  const out: string[] = [];
  renderNtRiscStatistics({ ...createEmptyExceptionDirectory([], "nt-risc32"), beginRvas: [1, 2],
    alphaPrologs: { resolvedSecondaryRanges: 1, unresolvedSecondaryRanges: 1 } }, out);
  assert.match(out.join(""), /Secondary ranges with known primary procedures<\/dt><dd>1<\/dd>/);
  assert.match(out.join(""), /Secondary ranges with missing primary procedures<\/dt><dd>1<\/dd>/);
  assert.match(out.join(""), /early Alpha NT scheme/);
  assert.doesNotMatch(out.join(""), /unresolved inline|prolog \(bytes\)/);
});

void test("NT RISC absent statistics add no empty detail", () => {
  const out: string[] = [];
  renderNtRiscStatistics(createEmptyExceptionDirectory([], "nt-risc32"), out);
  renderNtRiscStatistics({ ...createEmptyExceptionDirectory([], "nt-risc32"),
    alphaPrologs: { resolvedSecondaryRanges: 0, unresolvedSecondaryRanges: 0 } }, out);
  assert.deepEqual(out, []);
});
