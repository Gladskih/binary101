import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPeSectionPreview } from "../../../../renderers/pe/section-preview.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import type { PeImportEntry } from "../../../../analyzers/pe/imports/index.js";
import type { PeParseResult } from "../../../../analyzers/pe/index.js";
import type { ParsedWinCertificate } from "../../../../analyzers/pe/authenticode/index.js";
import { parseForUi } from "../../../../analyzers/index.js";
import { createPeRomFile } from "../../../fixtures/sample-files-pe.js";

const certificate = (): ParsedWinCertificate => ({ offset: 0, length: 8, availableBytes: 8,
  revision: 0x200, revisionName: "2.0", certificateType: 2, typeName: "PKCS#7" });
const moduleEntry = (dll: string): PeImportEntry => ({ dll, originalFirstThunkRva: 0,
  firstThunkRva: 0, timeDateStamp: 0, forwarderChain: 0, functions: [],
  lookupSource: "missing", thunkTableTerminated: false });

void test("PE previews name their source fields and retain the raw Machine value", () => {
  const pe = createBasePe();
  pe.opt.AddressOfEntryPoint = 0x1000;

  const header = renderPeSectionPreview(pe, "pe-headers");

  assert.match(header, /COFF.Machine<\/dt><dd>0x014c \(x86 \(I386\)\)/);
  assert.match(header, /^<dl class="workspaceCard__fields">/);
  assert.match(header, /OptionalHeader.AddressOfEntryPoint<\/dt><dd>0x00001000/);
  assert.match(header, /OptionalHeader.Subsystem<\/dt><dd>0x0002 \(Windows GUI\)/);
  assert.doesNotMatch(header, /Architecture|safe|malicious/);
  assert.match(renderPeSectionPreview(pe, "dos-header"), /e_magic<\/dt><dd>MZ/);
  assert.match(renderPeSectionPreview(pe, "dos-header"), /0x00000080/);
});

void test("unknown Machine values and missing or ROM optional headers stay explicit", async () => {
  const pe = createBasePe();
  pe.coff.Machine = 0xffff;
  const incomplete: PeParseResult = { ...pe, opt: null };
  const result = await parseForUi(createPeRomFile());
  assert.ok(result.analyzer === "pe");
  const rom = result.parsed;

  assert.match(renderPeSectionPreview(incomplete, "pe-headers"), /0xffff<\/dd>/);
  assert.doesNotMatch(renderPeSectionPreview(incomplete, "pe-headers"), /OptionalHeader/);
  assert.doesNotMatch(renderPeSectionPreview(rom, "pe-headers"), /Subsystem/);
  assert.equal(renderPeSectionPreview(rom, "security"), "");
  assert.equal(renderPeSectionPreview(rom, "imports"), "");
  assert.equal(renderPeSectionPreview(rom, "resources"), "");
});

void test("import previews retain names, show omitted descriptor counts and report parser warnings", () => {
  const pe = createBasePe();
  pe.imports.entries = [moduleEntry("<first>.dll"), moduleEntry(""), moduleEntry("third.dll"),
    moduleEntry("fourth.dll")];
  pe.imports.warning = "<recorded warning>";

  const html = renderPeSectionPreview(pe, "imports");

  assert.match(html, /&lt;first&gt;.dll/);
  assert.match(html, /empty DLL name/);
  assert.match(html, /third.dll/);
  assert.doesNotMatch(html, /fourth.dll/);
  assert.match(html, /<p class="smallNote">1 more<\/p>/);
  assert.match(html, /&lt;recorded warning&gt;/);
  pe.imports.entries.pop();
  assert.doesNotMatch(renderPeSectionPreview(pe, "imports"), /more/);
});

void test("empty imports, missing resources, missing security and unknown destinations add no facts", () => {
  const pe = createBasePe();

  assert.equal(renderPeSectionPreview(pe, "imports"), "");
  assert.equal(renderPeSectionPreview(pe, "resources"), "");
  assert.equal(renderPeSectionPreview(pe, "security"), "");
  assert.equal(renderPeSectionPreview(pe, "unknown"), "");
  pe.resources = { top: [], detail: [], issues: ["<resource issue>"] };
  assert.match(renderPeSectionPreview(pe, "resources"), /&lt;resource issue&gt;/);
});

void test("security previews distinguish unreported checks, an empty report and mixed outcomes", () => {
  const pe = createBasePe();
  const record = certificate();
  pe.security = { count: 1, certs: [record] };

  assert.match(renderPeSectionPreview(pe, "security"), /Not reported/);
  record.authenticode = { format: "pkcs7", verification: { checks: [] } };
  pe.security.certs.push(certificate());
  assert.match(renderPeSectionPreview(pe, "security"), /verification.checks<\/dt><dd>0/);
  record.authenticode.verification!.checks = [
    { id: "digest", title: "Digest", status: "pass" },
    { id: "signature", title: "Signature", status: "fail" },
    { id: "trust", title: "Trust", status: "unknown" }
  ];
  const html = renderPeSectionPreview(pe, "security");
  assert.match(html, /Recorded verification.checks<\/dt><dd>3/);
  assert.match(html, /pass: 1 · fail: 1 · unknown: 1/);
  assert.doesNotMatch(html, /safe|trusted file|valid signature/i);
});
