import assert from "node:assert/strict";
import { test } from "node:test";
import { renderUnwindCounts, renderUnwindSizes } from "../../../../renderers/pe/unwind-inventories.js";

void test("unwind inventories omit empty tables, escape labels and sort counts with numeric ties", () => {
  assert.equal(renderUnwindCounts("Empty", "Name", {}), "");
  assert.equal(renderUnwindSizes("Empty", {}), "");
  const html = renderUnwindCounts("<caption>", "<heading>", { R10: 1, R2: 1, "<op>&amp;": 2 });

  assert.match(html, /&lt;caption&gt;/);
  assert.match(html, /&lt;heading&gt;/);
  assert.match(html, /&lt;op&gt;&amp;amp;/);
  assert.ok(html.indexOf("&lt;op") < html.indexOf("R2"));
  assert.ok(html.indexOf("R2") < html.indexOf("R10"));
  assert.match(html, /class="peNumeric">2/);
});

void test("unwind sizes aggregate exact counts into ordered byte, KiB, MiB and GiB ranges", () => {
  const html = renderUnwindSizes("Sizes", { 33: 2, 32: 3, 0: 1, 1024: 1, 1048576: 1, 4294967288: 1 });

  assert.match(html, /0 bytes<\/td><td class="peNumeric">1/);
  assert.match(html, /32 B to &lt; 64 B<\/td><td class="peNumeric">5/);
  assert.match(html, /1 KiB to &lt; 2 KiB/);
  assert.match(html, /1 MiB to &lt; 2 MiB/);
  assert.match(html, /2 GiB to &lt; 4 GiB/);
  assert.ok(html.indexOf("0 bytes") < html.indexOf("32 B"));
  assert.match(renderUnwindSizes("Sizes", { 8: 1 }, "Allocation size"), /<th>Allocation size<\/th>/);
});
