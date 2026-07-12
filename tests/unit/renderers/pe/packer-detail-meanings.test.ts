"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { packerDetailMeaning } from "../../../../renderers/pe/packer-detail-meanings.js";

void test("packerDetailMeaning explains every detail emitted by the packaging analyzers", () => {
  assert.deepEqual(
    Object.fromEntries([
      "Compressed header length",
      "firstheader offset",
      "Flags",
      "Following data length",
      "Installer data range"
    ].map(label => [label, packerDetailMeaning(label)])),
    {
      "Compressed header length": "Declared compressed size of the NSIS header block.",
      "firstheader offset": "File offset of the validated NSIS first header.",
      "Flags": "Decoded format-specific flags.",
      "Following data length": "Declared size of installer data following the first header.",
      "Installer data range": "Validated file range covered by the NSIS installer data."
    }
  );
});

void test("packerDetailMeaning explains future analyzer-specific details generically", () => {
  assert.equal(packerDetailMeaning("Future field"), "Additional analyzer-specific metadata.");
});
