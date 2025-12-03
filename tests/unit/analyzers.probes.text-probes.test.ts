"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { probeTextLike } from "../../analyzers/probes/text-probes.js";

const dvFrom = (text: string): DataView => new DataView(new TextEncoder().encode(text).buffer);

void test("probeTextLike identifies HTML, XML, JSON and plain text", () => {
  assert.strictEqual(probeTextLike(dvFrom("<!doctype html><html></html>")), "HTML document");
  assert.strictEqual(probeTextLike(dvFrom('<?xml version="1.0"?><svg></svg>')), "SVG image (XML)");
  assert.strictEqual(probeTextLike(dvFrom('{ "foo": "bar" }')), "JSON data");
  assert.strictEqual(probeTextLike(dvFrom("plain text with spaces")), "Text file");
});

void test("probeTextLike returns null for binary-looking data", () => {
  const binary = new Uint8Array([0x00, 0xff, 0x10, 0x00]);
  assert.strictEqual(probeTextLike(new DataView(binary.buffer)), null);
});
