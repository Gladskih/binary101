"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDownloadButton } from "../../../renderers/download-button.js";

void test("renderDownloadButton renders shared download button markup", () => {
  const html = renderDownloadButton("Download <payload>", [
    ["data-pe-overlay-download"],
    ["data-overlay-start", 64],
    ["data-name", "a\"b"]
  ]);
  assert.ok(html.includes("class=\"downloadIconButton\""));
  assert.ok(html.includes("data-pe-overlay-download"));
  assert.ok(html.includes("data-overlay-start=\"64\""));
  assert.ok(html.includes("data-name=\"a&quot;b\""));
  assert.ok(html.includes("aria-label=\"Download &lt;payload>\""));
  assert.ok(html.includes("<svg aria-hidden=\"true\""));
});
