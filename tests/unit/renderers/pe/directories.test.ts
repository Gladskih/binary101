"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { inlinePeSectionName } from "../../../../analyzers/pe/sections/name.js";
import {
  renderExports,
  renderTls,
  renderIat,
  renderArchitectureDirectory,
  renderGlobalPtrDirectory
} from "../../../../renderers/pe/directories.js";

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

  assert.match(html, /<summary[^>]*><b>TLS directory<\/b> - unparsed<\/summary>/);
  assert.match(html, /<summary[^>]*><b>Import Address Table \(IAT\)<\/b><\/summary>/);
  assert.ok(html.includes("TLS directory RVA could not be mapped to a file offset."));
  assert.ok(html.includes("IAT directory RVA could not be mapped to a file offset."));
});

void test("renderTls displays parsed callback RVAs", () => {
  const tls: Parameters<typeof renderTls>[0] = {
    StartAddressOfRawData: 0x1000n,
    EndAddressOfRawData: 0x1010n,
    AddressOfIndex: 0x1020n,
    AddressOfCallBacks: 0x1030n,
    SizeOfZeroFill: 0,
    Characteristics: 0,
    CallbackCount: 2,
    CallbackRvas: [0x2000, 0x2010],
    parsed: true
  };
  const out: string[] = [];
  renderTls(tls, out);
  const html = out.join("");

  assert.match(html, /<th>Field<\/th><th>Value<\/th><th>Meaning<\/th>/);
  assert.ok(html.includes('<col style="width:11rem"><col style="width:1%"><col>'));
  assert.ok(html.includes('<td class="peNumeric" style="white-space:nowrap">0x1000</td>'));
  assert.match(
    html,
    /<th scope="row">StartAddressOfRawData<\/th><td class="peNumeric" style="white-space:nowrap">0x1000<\/td>/
  );
  assert.ok(html.includes("VA for beginning of TLS template data."));
  assert.doesNotMatch(html, /<dl>/);
  assert.ok(html.includes("Callback RVAs"));
  assert.ok(html.includes("0x00002000"));
  assert.ok(html.includes("0x00002010"));
});

void test("renderTls explains TLS Characteristics alignment and reserved bits", () => {
  const tls: Parameters<typeof renderTls>[0] = {
    StartAddressOfRawData: 0x1000n,
    EndAddressOfRawData: 0x1010n,
    AddressOfIndex: 0x1020n,
    AddressOfCallBacks: 0n,
    SizeOfZeroFill: 0,
    Characteristics: 0x00500001,
    CallbackCount: 0,
    CallbackRvas: [],
    parsed: true
  };
  const out: string[] = [];
  renderTls(tls, out);
  const html = out.join("");

  assert.ok(html.includes("0x00500001"));
  assert.ok(html.includes("<th scope=\"row\">Characteristics</th>"));
  assert.ok(html.includes('<td style="white-space:nowrap"><div class="mono">0x00500001</div>'));
  assert.ok(html.includes("flex-direction:column"));
  assert.ok(
    html.includes(
      'class="opt dim" style="white-space:nowrap" data-accessible-tooltip title="Align TLS data copied for each thread to 1 byte.'
    )
  );
  assert.ok(
    html.includes(
      'class="opt sel" style="white-space:nowrap" data-accessible-tooltip title="Align TLS data copied for each thread to 16 bytes.'
    )
  );
  assert.ok(html.includes(">IMAGE_SCN_ALIGN_8192BYTES</span>"));
  assert.ok(
    html.includes(
      'class="opt sel" style="white-space:nowrap" data-accessible-tooltip title="Reserved TLS Characteristics bits are set: 0x00000001."'
    )
  );
  assert.ok(
    html.includes(
      "Bits 20-23 encode the preferred alignment for TLS data copied for each thread; all other bits are reserved."
    )
  );
  assert.ok(!html.includes("Requests 16-byte alignment."));
  assert.ok(!html.includes("Other 28 bits are reserved and clear."));
  assert.ok(html.includes(">RESERVED_BITS_0x00000001</span>"));
  assert.ok(!html.includes("RESERVED_CLEAR"));
  assert.doesNotMatch(
    html,
    /<td class="smallNote">[^<]*IMAGE_SCN_ALIGN_16BYTES/
  );
  assert.ok(!html.includes("Reserved (should be 0)."));
});

void test("renderTls shows an unknown TLS Characteristics alignment chip", () => {
  const tls: Parameters<typeof renderTls>[0] = {
    StartAddressOfRawData: 0x1000n,
    EndAddressOfRawData: 0x1010n,
    AddressOfIndex: 0x1020n,
    AddressOfCallBacks: 0n,
    SizeOfZeroFill: 0,
    Characteristics: 0x00f00000,
    CallbackCount: 0,
    CallbackRvas: [],
    parsed: true
  };
  const out: string[] = [];
  renderTls(tls, out);
  const html = out.join("");

  assert.ok(
    html.includes(
      'class="opt sel" style="white-space:nowrap" data-accessible-tooltip title="Unknown TLS Characteristics alignment value 0x00f00000."'
    )
  );
  assert.ok(html.includes("UNKNOWN_ALIGNMENT_0x00f00000"));
});

void test("renderExports renders entries directly without a nested show wrapper", () => {
  const exportsSection: Parameters<typeof renderExports>[0] = {
    flags: 0,
    timestamp: 0,
    version: 0,
    dllName: "demo.dll",
    Base: 1,
    NumberOfFunctions: 1,
    NumberOfNames: 1,
    namePointerTable: 0,
    ordinalTable: 0,
    entries: [{ ordinal: 1, name: "Demo", rva: 0x1234, forwarder: null }],
    issues: []
  };
  const out: string[] = [];
  renderExports(exportsSection, out);
  const html = out.join("");

  assert.ok(html.includes("Export directory"));
  assert.ok(html.includes("Demo"));
  assert.ok(!html.includes("Show entries"));
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
    sections: [{ name: inlinePeSectionName(GP_REL_TEST_SECTION_NAME), characteristics: 0x00008000 }]
  } as unknown as Parameters<typeof renderArchitectureDirectory>[0];
  const out: string[] = [];
  renderArchitectureDirectory(pe, out);
  renderGlobalPtrDirectory(pe, out);
  const html = out.join("");

  assert.match(html, /<summary[^>]*><b>Architecture directory<\/b> - reserved slot<\/summary>/);
  assert.ok(html.includes("reserved by the PE specification"));
  assert.match(html, /<summary[^>]*><b>Global pointer \(GP\)<\/b> - 1 GP-relative section<\/summary>/);
  assert.ok(html.includes("Value RVA"));
  assert.ok(html.includes(GP_REL_TEST_SECTION_NAME));
  assert.ok(html.includes("IMAGE_SCN_GPREL"));
});
