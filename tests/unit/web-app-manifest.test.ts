"use strict";

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const indexHtml = readFileSync("index.html", "utf8");
const manifest = JSON.parse(readFileSync("public/site.webmanifest", "utf8")) as {
  name?: string;
  short_name?: string;
  id?: string;
  start_url?: string;
  scope?: string;
  display?: string;
  icons?: Array<{
    src?: string;
    sizes?: string;
    type?: string;
    purpose?: string;
  }>;
};

void test("index links the web app manifest and allows it through CSP", () => {
  assert.match(indexHtml, /<link rel="manifest" href="\.\/site\.webmanifest">/);
  assert.match(indexHtml, /manifest-src\s+'self'/);
});

void test("web app manifest defines install metadata and scoped local launch", () => {
  assert.equal(manifest.name, "Binary101 Local File Inspector");
  assert.equal(manifest.short_name, "Binary101");
  assert.equal(manifest.id, ".");
  assert.equal(manifest.start_url, ".");
  assert.equal(manifest.scope, ".");
  assert.equal(manifest.display, "standalone");
});

void test("web app manifest reuses the SVG favicon as regular and maskable icon", () => {
  assert.deepEqual(manifest.icons, [
    {
      src: "favicon.svg",
      sizes: "any",
      type: "image/svg+xml",
      purpose: "any maskable"
    }
  ]);
});
