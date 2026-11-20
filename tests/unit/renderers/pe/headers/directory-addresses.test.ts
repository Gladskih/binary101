import assert from "node:assert/strict";
import { test } from "node:test";
import { renderHeaders } from "../../../../../renderers/pe/headers.js";
import { createDebugViewEntry } from "../../../../fixtures/pe-debug-view-subject.js";
import { createBasePe } from "../../../../fixtures/pe-renderer-headers-fixture.js";

void test("renderHeaders labels certificate offsets and keeps REPRO stamps numeric", () => {
  const pe = createBasePe();
  // IMAGE_DEBUG_TYPE_REPRO is 16. The stamp is from .NET 10.0.8 System.Console.dll.
  pe.debug = { entry: null, entries: [createDebugViewEntry(16, 0, 0, 0)] };
  pe.coff.TimeDateStamp = 0x9e756b5c;
  pe.dirs = [{ index: 4, name: "SECURITY", rva: 0x2000, size: 0x10 }];

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.match(html, />Address<\/th>/);
  assert.match(html, /0x00002000[^<]*<[^>]+>File offset/);
  assert.match(html, />TimeDateStamp<\/dt><dd>0x9e756b5c<\/dd>/i);
  assert.doesNotMatch(html, /2054-03-30/);
});

void test("renderHeaders identifies the PE no-timestamp marker", () => {
  const pe = createBasePe();
  // Microsoft PE Format, General Concepts: 0xffffffff has no time interpretation.
  pe.coff.TimeDateStamp = 0xffffffff;

  const out: string[] = [];
  renderHeaders(pe, out);

  assert.match(out.join(""), />TimeDateStamp<\/dt><dd>0xffffffff \(no timestamp\)<\/dd>/);
});
