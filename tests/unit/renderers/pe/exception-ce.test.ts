import assert from "node:assert/strict";
import { test } from "node:test";
import { renderCeExceptionStatistics } from "../../../../renderers/pe/exception-ce.js";
import { renderException } from "../../../../renderers/pe/exception.js";
import { createEmptyExceptionDirectory } from "../../../../analyzers/pe/exception/types.js";

void test("CE statistics summarize instruction widths, handler sharing and byte-sized prologs", () => {
  const out: string[] = [];
  renderCeExceptionStatistics({ ...createEmptyExceptionDirectory([], "ce"), handlerRvas: [0x1100],
    ceCompressed: { instruction16Count: 2, instruction32Count: 3, extendedEntryCount: 0, handlerDataCount: 4,
      prologs: { count: 5, empty: 1, minimumBytes: 0, maximumBytes: 12 } } }, out);
  const html = out.join("");

  assert.match(html, /16-bit instruction entries<\/dt><dd>2<\/dd>/);
  assert.match(html, /32-bit instruction entries<\/dt><dd>3<\/dd>/);
  assert.match(html, /Unique resolved handlers<\/dt><dd>1<\/dd>/);
  assert.match(html, /Nonzero handler data pointers<\/dt><dd>4<\/dd>/);
  assert.match(html, /Prologs with resolved lengths<\/dt><dd>5<\/dd>/);
  assert.match(html, /Empty prologs<\/dt><dd>1<\/dd>/);
  assert.match(html, /Shortest prolog \(bytes\)<\/dt><dd>0<\/dd>/);
  assert.match(html, /Longest prolog \(bytes\)<\/dt><dd>12<\/dd>/);
  assert.doesNotMatch(html, /unresolved extended|<table|0x1100/);
});

void test("CE statistics retain unresolved extended lengths and omit absent prolog detail", () => {
  const out: string[] = [];
  renderCeExceptionStatistics({ ...createEmptyExceptionDirectory([], "ce"),
    ceCompressed: { instruction16Count: 0, instruction32Count: 1, extendedEntryCount: 1, handlerDataCount: 0 } }, out);

  assert.match(out.join(""), /Entries with unresolved extended lengths<\/dt><dd>1<\/dd>/);
  assert.doesNotMatch(out.join(""), /Empty prologs|Shortest prolog|Longest prolog/);
});

void test("CE renderer uses its own VA profile and no fabricated chained-entry count", () => {
  const out: string[] = [];
  const statistics: string[] = [];
  renderException(createEmptyExceptionDirectory([], "ce"), out);
  renderCeExceptionStatistics(createEmptyExceptionDirectory([], "ce"), statistics);

  assert.deepEqual(statistics, []);
  assert.match(out.join(""), /Windows CE .pdata stores virtual function addresses/);
  assert.match(out.join(""), /Associated handler metadata immediately precedes the function/);
  assert.match(out.join(""), /Inline function descriptions/);
  assert.match(out.join(""), /Functions with handler metadata/);
  assert.doesNotMatch(out.join(""), /UNWIND_INFO|CHAININFO|EHANDLER|chained|undefined/);
});
