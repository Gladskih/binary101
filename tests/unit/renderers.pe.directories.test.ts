"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  renderTls,
  renderIat,
  renderArchitectureDirectory,
  renderGlobalPtrDirectory
} from "../../renderers/pe/directories.js";

const GP_REL_TEST_SECTION_NAME = "GP_TEST";

void test("renderTls and renderIat display local directory warnings", () => {
  const tls: Parameters<typeof renderTls>[0] = {
    StartAddressOfRawData: 0n,
    EndAddressOfRawData: 0n,
    AddressOfIndex: 0n,
    AddressOfCallBacks: 0n,
    SizeOfZeroFill: 0,
    Characteristics: 0,
    CallbackCount: 0,
    CallbackRvas: [],
    warnings: ["TLS directory RVA could not be mapped to a file offset."],
    parsed: false
  };
  const iat: Parameters<typeof renderIat>[0] = {
    // Renderer-only fixture: these RVA/Size values are incidental because the test asserts
    // warning rendering, not directory geometry.
    rva: 0x1000,
    size: 0x20,
    warnings: ["IAT directory RVA could not be mapped to a file offset."]
  };

  const out: string[] = [];
  renderTls(tls, out);
  renderIat(iat, out);
  const html = out.join("");

  assert.ok(html.includes("TLS directory RVA could not be mapped to a file offset."));
  assert.ok(html.includes("IAT directory RVA could not be mapped to a file offset."));
});

void test("renderArchitectureDirectory and renderGlobalPtrDirectory explain their own directories", () => {
  const pe = {
    architecture: {
      // Any non-zero RVA/Size pair is anomalous here because ARCHITECTURE is reserved.
      rva: 0x1200,
      size: 0x10,
      warnings: ["ARCHITECTURE directory is reserved by the PE specification and should have RVA=0 and Size=0."]
    },
    globalPtr: {
      // Exact RVA is incidental in this renderer-only test; it just needs to be non-zero.
      rva: 0x1100,
      size: 0,
      warnings: []
    },
    // Microsoft PE format, "Section Flags": IMAGE_SCN_GPREL (0x00008000).
    sections: [{ name: GP_REL_TEST_SECTION_NAME, characteristics: 0x00008000 }]
  } as unknown as Parameters<typeof renderArchitectureDirectory>[0];
  const out: string[] = [];
  renderArchitectureDirectory(pe, out);
  renderGlobalPtrDirectory(pe, out);
  const html = out.join("");

  assert.ok(html.includes("Architecture directory"));
  assert.ok(html.includes("reserved by the PE specification"));
  assert.ok(html.includes("Global pointer (GP)"));
  assert.ok(html.includes("Value RVA"));
  assert.ok(html.includes(GP_REL_TEST_SECTION_NAME));
  assert.ok(html.includes("IMAGE_SCN_GPREL"));
});
