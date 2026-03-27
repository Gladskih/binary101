"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  addDialogIncludePreview,
  addFontDirectoryPreview,
  addFontPreview,
  addPlugPlayPreview,
  addRcDataPreview,
  addVxdPreview
} from "../../analyzers/pe/resources-preview-standard-types.js";

const encoder = new TextEncoder();

// WHATWG MIME Sniffing identifies TrueType/OpenType sfnt payloads by the 0x00010000 scaler.
// Source: https://mimesniff.spec.whatwg.org/#matching-a-font-type-pattern
const buildTrueTypeSignaturePayload = (): Uint8Array =>
  new Uint8Array([0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80]);

void test("standard PE resource decoders cover long-tail standard resource types", async () => {
  const rcdata = await addRcDataPreview(encoder.encode("{\"kind\":\"rcdata\"}\n"), "RCDATA", 65001);
  const font = await addFontPreview(buildTrueTypeSignaturePayload(), "FONT");
  const fontDir = addFontDirectoryPreview(new Uint8Array([1, 0, 0, 0]), "FONTDIR");
  const dlgInclude = addDialogIncludePreview(
    encoder.encode("#include \"preview-dialog.h\"\n"),
    "DLGINCLUDE",
    65001
  );
  const plugPlay = addPlugPlayPreview(new Uint8Array([0x50, 0x4e, 0x50, 0x00]), "PLUGPLAY");
  const vxd = addVxdPreview(new Uint8Array([0x56, 0x58, 0x44, 0x00]), "VXD");

  assert.strictEqual(rcdata?.preview?.previewKind, "text");
  assert.strictEqual(font?.preview?.previewKind, "font");
  assert.strictEqual(fontDir?.preview?.previewKind, "summary");
  assert.strictEqual(dlgInclude?.preview?.previewKind, "text");
  assert.strictEqual(plugPlay?.preview?.previewKind, "summary");
  assert.strictEqual(vxd?.preview?.previewKind, "summary");
});
