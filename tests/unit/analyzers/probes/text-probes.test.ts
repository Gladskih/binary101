"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { probeTextLike } from "../../../../analyzers/probes/text-probes.js";

const dvFrom = (text: string): DataView => new DataView(new TextEncoder().encode(text).buffer);
const utf16LeDvFrom = (text: string): DataView => {
  const bytes = new Uint8Array(2 + text.length * 2);
  bytes[0] = 0xff;
  bytes[1] = 0xfe;
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < text.length; index += 1) {
    view.setUint16(2 + index * 2, text.charCodeAt(index), true);
  }
  return view;
};

void test("probeTextLike identifies HTML, XML, JSON and plain text", () => {
  assert.strictEqual(probeTextLike(dvFrom("<!doctype html><html></html>")), "HTML document");
  assert.strictEqual(probeTextLike(dvFrom('<?xml version="1.0"?><svg></svg>')), "SVG image (XML)");
  assert.strictEqual(probeTextLike(dvFrom('{ "foo": "bar" }')), "JSON data");
  assert.strictEqual(probeTextLike(dvFrom("plain text with spaces")), "Text file");
});

void test("probeTextLike identifies Windows INF setup scripts", () => {
  const inf = [
    "; sample INF",
    "[Version]",
    'Signature="$Windows NT$"',
    "Class=System"
  ].join("\r\n");
  const label = "Windows setup information file (INF, driver/install directives)";
  assert.strictEqual(probeTextLike(dvFrom(inf)), label);
  assert.strictEqual(probeTextLike(utf16LeDvFrom(inf)), label);
});

void test("probeTextLike treats UTF-16 text with BOM as text", () => {
  assert.strictEqual(probeTextLike(utf16LeDvFrom("plain text")), "Text file");
});

void test("probeTextLike identifies PEM armor blocks", () => {
  const pem = [
    "-----BEGIN CERTIFICATE-----",
    "QUJD",
    "-----END CERTIFICATE-----"
  ].join("\n");
  assert.strictEqual(probeTextLike(dvFrom(pem)), "PEM armor block (certificate/key text encoding)");
});

void test("probeTextLike identifies PostScript documents", () => {
  assert.strictEqual(
    probeTextLike(dvFrom("%!PS-Adobe-3.0\n%%Title: sample")),
    "PostScript document (page description program)"
  );
});

void test("probeTextLike identifies PostScript Printer Description files", () => {
  assert.strictEqual(
    probeTextLike(dvFrom("*PPD-Adobe: \"4.3\"\n*FormatVersion: \"4.3\"")),
    "PostScript Printer Description file (PPD printer driver metadata)"
  );
});

void test("probeTextLike returns null for binary-looking data", () => {
  const binary = new Uint8Array([0x00, 0xff, 0x10, 0x00]);
  assert.strictEqual(probeTextLike(new DataView(binary.buffer)), null);
});
