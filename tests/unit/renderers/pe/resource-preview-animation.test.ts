import assert from "node:assert/strict";
import { test } from "node:test";
import { renderResourceAnimation } from "../../../../renderers/pe/resource-preview-animation.js";
void test("retains ANI sequence/rate metadata, hotspots and absent frame placeholders", () => {
  const html = renderResourceAnimation({ frames: [{ url: "data:image/png;base64,AQ==", hotspot: {x: 2, y: 3} },
    {url: ""}], flags: 3, sequence: [1, 0], rates: [6], defaultJiffies: 12, declaredFrames: 2, declaredSteps: 2 });
  assert.match(html, /data-pe-animation-steps="1:100,0:200"/);
  assert.match(html, /hotspot 2, 3/);
  assert.doesNotMatch(html, /src=""/);
  assert.match(html, /Frame 2 is unavailable/);
});
void test("does not apply a sequence without AF_SEQUENCE", () => {
  const html = renderResourceAnimation({frames:[{url:""}], flags:1, sequence:[9], rates:[],
    defaultJiffies:1, declaredFrames:1, declaredSteps:1});
  assert.match(html, /data-pe-animation-steps="0:/);
});
