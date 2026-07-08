"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { probeTextLike } from "../../../../analyzers/probes/text-probes.js";

const dvFrom = (text: string): DataView => new DataView(new TextEncoder().encode(text).buffer);
const utf8BomDvFrom = (text: string): DataView => {
  const encoded = new TextEncoder().encode(text);
  const bytes = new Uint8Array(3 + encoded.length);
  bytes.set([0xef, 0xbb, 0xbf]);
  bytes.set(encoded, 3);
  return new DataView(bytes.buffer);
};
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
  assert.strictEqual(probeTextLike(dvFrom('<svg xmlns="http://www.w3.org/2000/svg"></svg>')), "SVG image (XML)");
  assert.strictEqual(probeTextLike(dvFrom("<root><value>1</value></root>")), "XML document");
  assert.strictEqual(probeTextLike(utf8BomDvFrom('<?xml version="1.0"?><root/>')), "XML document");
  assert.strictEqual(
    probeTextLike(utf8BomDvFrom(`<?xml version="1.0"?><!--${"x".repeat(300)}--><root/>`)),
    "XML document"
  );
  assert.strictEqual(probeTextLike(dvFrom('{ "foo": "bar" }')), "JSON data");
  assert.strictEqual(probeTextLike(dvFrom('[{ "title": "日本語" }]')), "JSON data");
  assert.strictEqual(probeTextLike(dvFrom("plain text with spaces")), "Text file");
});

void test("probeTextLike does not confuse bracketed text with JSON", () => {
  assert.strictEqual(probeTextLike(dvFrom("[core]\nrepositoryformatversion = 1")), "Text file");
  assert.strictEqual(probeTextLike(dvFrom("[0619/221624.164:WARNING] message")), "Text file");
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
