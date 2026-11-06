import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSwf } from "../../../renderers/swf.js";
import type { SwfParseResult } from "../../../analyzers/swf/types.js";

const parsed = (): SwfParseResult => ({ signature: "FWS", version: 9, fileLength: 100,
  movie: { xMin: 0, xMax: 12800, yMin: 0, yMax: 9600, frameRate: 7680, frameCount: 2 },
  fileAttributes: 25, tags: [{ code: 82, count: 2, bodyBytes: 20 }, { code: 999, count: 1, bodyBytes: 1 }],
  issues: ["<bad>"] });

void test("renderSwf shows movie properties and aggregated numeric tag counts while escaping diagnostics", () => {
  const html = renderSwf(parsed());

  assert.match(html, /640 × 480 pixels/);
  assert.match(html, /30 fps/);
  assert.match(html, /ActionScript 3/);
  assert.match(html, /Network access/);
  assert.match(html, /DoABC<\/td><td class="peNumeric">2/);
  assert.match(html, /999<\/td><td>Unknown tag/);
  assert.match(html, /&lt;bad/);
  assert.ok(!html.includes("<bad>"));
});

void test("renderSwf keeps compressed body checks explicitly pending and omits unknown movie properties", () => {
  const html = renderSwf({ signature: "ZWS", version: 13, fileLength: 100, issues: [] }, 32, 64);
  const avm1 = renderSwf({ signature: "CWS", version: 8, fileLength: 100, fileAttributes: 0,
    tags: [], issues: [] });

  assert.match(html, /LZMA/);
  assert.match(html, /Automatic background analysis/);
  assert.match(html, /data-swf-start="32" data-swf-end="64"/);
  assert.match(html, /data-swf-body-status/);
  assert.ok(!html.includes("Stage size"));
  assert.ok(!html.includes("<table"));
  assert.match(avm1, /zlib/);
  assert.match(avm1, /ActionScript 1\/2/);
  assert.match(avm1, /Local file access/);
  assert.ok(!avm1.includes("data-swf-body-status"));
});
