"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { probeByMagic, probeTextLike } from "../../analyzers/probes.js";

const dvFrom = bytes => new DataView(new Uint8Array(bytes).buffer);

test("probeByMagic identifies common signatures", () => {
  assert.strictEqual(
    probeByMagic(dvFrom([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
    "PNG image"
  );

  assert.strictEqual(
    probeByMagic(
      dvFrom([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37]) // %PDF-1.7
    ),
    "PDF document"
  );

  assert.strictEqual(
    probeByMagic(dvFrom([0x50, 0x4b, 0x03, 0x04])), // PK..
    "ZIP archive (PK-based, e.g. Office, JAR, APK)"
  );

  assert.strictEqual(
    probeByMagic(dvFrom([0x47, 0x49, 0x46, 0x38, 0x39, 0x61])), // GIF89a
    "GIF image"
  );
});

test("probeByMagic covers varied archive and container signatures", () => {
  const sevenZip = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x00];
  assert.strictEqual(probeByMagic(dvFrom(sevenZip)), "7z archive");

  const rar = [...Buffer.from("Rar!\u001a\u0007", "binary"), 0x00];
  assert.strictEqual(probeByMagic(dvFrom(rar)), "RAR archive");

  const asfGuid = [
    0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11,
    0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c
  ];
  assert.strictEqual(probeByMagic(dvFrom(asfGuid)), "ASF container (WMA/WMV)");

  const isoBmff = new Uint8Array(12);
  const isoDv = new DataView(isoBmff.buffer);
  isoDv.setUint32(4, 0x66747970, false); // 'ftyp'
  isoDv.setUint32(8, 0x6d703432, false); // 'mp42'
  assert.strictEqual(probeByMagic(isoDv), "MP4/QuickTime container (ISO-BMFF)");

  const tarBytes = new Uint8Array(300);
  tarBytes.set([0x75, 0x73, 0x74, 0x61, 0x72], 257); // "ustar"
  assert.strictEqual(probeByMagic(new DataView(tarBytes.buffer)), "TAR archive");
});

test("probeTextLike classifies plain text and HTML-like payloads", () => {
  const html = "<!doctype html><html><body>Hello</body></html>";
  const htmlDv = dvFrom([...Buffer.from(html, "utf-8")]);
  assert.strictEqual(probeTextLike(htmlDv), "HTML document");

  const text = "plain text without special markers";
  const textDv = dvFrom([...Buffer.from(text, "utf-8")]);
  assert.strictEqual(probeTextLike(textDv), "Text file");
});

test("probeTextLike recognizes XML, SVG, JSON and FB2 markers", () => {
  const svg = '<?xml version="1.0"?><svg><rect/></svg>';
  const svgDv = dvFrom([...Buffer.from(svg, "utf-8")]);
  assert.strictEqual(probeTextLike(svgDv), "SVG image (XML)");

  const fb2 = '<?xml version="1.0" encoding="UTF-8"?><FictionBook><body/></FictionBook>';
  const fb2Dv = dvFrom([...Buffer.from(fb2, "utf-8")]);
  assert.strictEqual(probeTextLike(fb2Dv), "FictionBook e-book (FB2)");

  const json = '{ "hello": "world" }';
  const jsonDv = dvFrom([...Buffer.from(json, "utf-8")]);
  assert.strictEqual(probeTextLike(jsonDv), "JSON data");
});
