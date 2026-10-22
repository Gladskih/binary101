import assert from "node:assert/strict";
import { test } from "node:test";
import { renderException } from "../../../../renderers/pe/exception.js";
import { createEmptyExceptionDirectory } from "../../../../analyzers/pe/exception/types.js";

for (const [format, intro, unwindLabel] of [
  ["arm64", "ARM64 .pdata stores packed unwind data", "Unique unwind descriptions"],
  ["native-aot-x86", "NativeAOT x86 uses 12-byte RuntimeFunction", "Unique x86 UNWIND_INFO blocks"],
  ["ready-to-run-x86", "ReadyToRun x86 uses 8-byte RuntimeFunction", "Unique unwind blobs"]
] as const) {
  void test(`Exception renderer retains the ${format} format profile`, () => {
    const out: string[] = [];
    renderException(createEmptyExceptionDirectory([], format), out);
    const html = out.join("");

    assert.ok(html.includes(intro));
    assert.ok(html.includes(unwindLabel));
    assert.doesNotMatch(html, /Winding operations|UNWIND_INFO v3/);
  });
}

void test("ReadyToRun renders each exception-clause count once alongside its subtypes", () => {
  const out: string[] = [];
  renderException({ ...createEmptyExceptionDirectory([], "ready-to-run-x86"),
    handlerUnwindInfoCount: 4, exceptionClauseCount: 4, exceptionInfoMethodCount: 2,
    catchClauseCount: 1, filterClauseCount: 1, finallyClauseCount: 1, faultClauseCount: 1
  }, out);
  const html = out.join("");

  assert.equal([...html.matchAll(/<dt>Exception clauses<\/dt>/g)].length, 1);
  assert.match(html, /Exception clauses<\/dt><dd>4<\/dd>/);
  assert.match(html, /ExceptionInfo methods<\/dt><dd>2<\/dd>/);
  assert.match(html, /Catch clauses<\/dt><dd>1<\/dd>/);
  assert.match(html, /Filter clauses<\/dt><dd>1<\/dd>/);
  assert.match(html, /Finally clauses<\/dt><dd>1<\/dd>/);
  assert.match(html, /Fault clauses<\/dt><dd>1<\/dd>/);
});

void test("Exception renderer keeps readable diagnostics", () => {
  const out: string[] = [];
  renderException(createEmptyExceptionDirectory(["broken <metadata>"], "amd64"), out);

  assert.match(out.join(""), /Exception directory warnings/);
  assert.doesNotMatch(out.join(""), /<metadata>/);
});
