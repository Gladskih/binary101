"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDosHeader } from "../../../../renderers/pe/dos-header.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";

const VALVE_SIGNED_DATA_SIZE_FIXTURE_BYTES = 3_976_704;
// Valve Steam blocks carry a 128-byte RSA signature.
const VALVE_SIGNATURE_HEX_FIXTURE = "ab".repeat(0x80);

void test("renderDosHeader shows field hints inline instead of tooltip-only text", () => {
  const pe = createBasePe();
  const out: string[] = [];
  renderDosHeader(pe, out);
  const html = out.join("");
  assert.match(html, /<th>Field<\/th><th>Value<\/th><th>Meaning<\/th>/);
  assert.match(html, /<tr><th scope="row">e_magic<\/th><td>MZ<\/td><td class="smallNote"[^>]*>/);
  assert.match(html, /<td class="smallNote"[^>]*>DOS header signature\./);
  assert.doesNotMatch(html, /<dt title="DOS header signature\./);
  assert.doesNotMatch(html, /<dl>/);
});

void test("renderDosHeader escapes DOS stub strings", () => {
  const pe = createBasePe();
  pe.dos.stub = { kind: "stub", note: "<note>", strings: ["<stub text>"] };
  const out: string[] = [];
  renderDosHeader(pe, out);
  const html = out.join("");
  assert.ok(html.includes("DOS stub: stub - &lt;note>"));
  assert.ok(html.includes("&lt;stub text>"));
  assert.doesNotMatch(html, /<stub text>/);
});

void test("renderDosHeader renders DOS stub code as informational notes", () => {
  const pe = createBasePe();
  pe.dos.stub = {
    kind: "stub",
    note: "",
    code: {
      kind: "custom-or-unrecognized",
      messageOffset: 0x12,
      message: "hello <dos>",
      instructions: [{ offset: 0, text: "int <21h>" }],
      notes: ["stub <differs> from common pattern"]
    }
  };
  const out: string[] = [];
  renderDosHeader(pe, out);
  const html = out.join("");
  assert.ok(html.includes("DOS stub code: custom or unrecognized DOS code"));
  assert.ok(html.includes("Message target: +0012"));
  assert.ok(html.includes("hello &lt;dos>"));
  assert.ok(html.includes("<th>Offset</th><th>Instruction</th>"));
  assert.ok(html.includes("int &lt;21h>"));
  assert.ok(html.includes("stub &lt;differs> from common pattern"));
  assert.doesNotMatch(html, /WARNING/i);
});

void test("renderDosHeader does not expose internal standard stub pattern names", () => {
  const pe = createBasePe();
  pe.dos.stub = {
    kind: "standard",
    note: "DOS print-and-exit code",
    code: {
      kind: "standard-print-exit",
      messageOffset: 0x0e,
      message: "This program cannot be run in DOS mode.",
      instructions: [{ offset: 0, text: "push cs" }]
    }
  };
  const out: string[] = [];
  renderDosHeader(pe, out);
  const html = out.join("");
  assert.ok(html.includes("DOS stub: standard print-and-exit code"));
  assert.ok(html.includes("Message target: +000e"));
  assert.ok(html.includes("This program cannot be run in DOS mode."));
  assert.ok(html.includes("push cs"));
  assert.doesNotMatch(html, /DOS stub code: standard DOS print-and-exit/);
  assert.doesNotMatch(html, /push-pop-then-dx/);
});

void test("renderDosHeader renders nested PE download controls", () => {
  const pe = createBasePe();
  pe.dos.stub = {
    kind: "non-standard",
    note: "printable text",
    code: {
      kind: "custom-or-unrecognized",
      instructions: [],
      nestedPe: {
        offset: 0,
        endOffset: 0x2ce0,
        peHeaderOffset: 0xb0,
        machine: 0x014c,
        optionalMagic: 0x10b,
        entrypointRva: 0x314,
        subsystem: 16,
        sizeOfImage: 0x2ce0,
        sizeOfHeaders: 0x220,
        sections: [{
          name: "MLEINIT",
          virtualAddress: 0x220,
          virtualSize: 542,
          sizeOfRawData: 544,
          pointerToRawData: 0x220
        }],
        codeViewPath: "mlestartup.pdb",
        mle: {
          offset: 0x220,
          version: 0x20003,
          entryPoint: 0x314,
          firstValidPage: 0,
          mleStart: 0,
          mleEnd: 0x2ce0,
          capabilities: 0x440f
        }
      }
    }
  };
  const out: string[] = [];
  renderDosHeader(pe, out);
  const html = out.join("");
  assert.ok(html.includes("PE file for x86 (I386) found at offset"));
  assert.ok(html.includes("data-pe-dos-nested-download"));
  assert.ok(html.includes("data-nested-start=\"64\""));
  assert.ok(html.includes("data-nested-end=\"11552\""));
  assert.ok(html.includes("aria-label=\"Download nested PE\""));
  assert.ok(html.includes("<svg aria-hidden=\"true\""));
  assert.ok(html.includes("peDosNestedPe__header"));
  assert.doesNotMatch(html, /DOS stub: non-standard.*printable text/);
  assert.doesNotMatch(html, /mlestartup\.pdb/);
  assert.doesNotMatch(html, /MLEINIT/);
});

void test("renderDosHeader renders Valve integrity blocks as structured data", () => {
  const pe = createBasePe();
  pe.dos.e_lfanew = 0x158;
  pe.dos.stub = {
    kind: "valve-integrity",
    note: "Valve PE integrity block",
    valveIntegrity: {
      version: 1,
      signedDataSize: VALVE_SIGNED_DATA_SIZE_FIXTURE_BYTES,
      timestamp: 0x64d1f2a0,
      signatureHex: VALVE_SIGNATURE_HEX_FIXTURE,
      paddingSize: 0x88,
      paddingZeroFilled: true
    }
  };
  const out: string[] = [];
  renderDosHeader(pe, out);
  const html = out.join("");
  assert.ok(html.includes("DOS stub: Valve PE integrity block"));
  assert.ok(html.includes("Valve block found at file offset 0x00000040."));
  assert.ok(html.includes("<th scope=\"row\">Magic</th><td>VLV\\0</td>"));
  assert.ok(
    html.includes(
      `<th scope="row">Signed data size</th><td>3.8 MB (${VALVE_SIGNED_DATA_SIZE_FIXTURE_BYTES} bytes)</td>`
    )
  );
  assert.ok(html.includes(VALVE_SIGNATURE_HEX_FIXTURE));
  assert.ok(html.includes("<th scope=\"row\">Padding before PE header</th><td>136 B (136 bytes) (zero-filled)</td>"));
});
