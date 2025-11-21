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

test("probeTextLike classifies plain text and HTML-like payloads", () => {
  const html = "<!doctype html><html><body>Hello</body></html>";
  const htmlDv = dvFrom([...Buffer.from(html, "utf-8")]);
  assert.strictEqual(probeTextLike(htmlDv), "HTML document");

  const text = "plain text without special markers";
  const textDv = dvFrom([...Buffer.from(text, "utf-8")]);
  assert.strictEqual(probeTextLike(textDv), "Text file");
});
