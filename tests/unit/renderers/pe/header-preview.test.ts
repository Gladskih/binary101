import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPeHeaderPreview } from "../../../../renderers/pe/header-preview.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createPeRomFile } from "../../../fixtures/sample-files-pe.js";
import { parseForUi } from "../../../../analyzers/index.js";
import { readOverviewFacts } from "../../../helpers/overview-card-fixture.js";

void test("header highlights name the source enum fields and the entry point", () => {
  const pe = createBasePe();
  pe.opt.AddressOfEntryPoint = 0x1234;

  const html = renderPeHeaderPreview(pe);

  assert.deepEqual(readOverviewFacts(html), [["Machine", "x86 (I386)"],
    ["Subsystem", "Windows GUI"], ["AddressOfEntryPoint", "0x00001234"]]);
  assert.doesNotMatch(html, /Architecture|0x014c|<table|<dl|LinkerVersion|SizeOfCode/);
});

void test("unknown enum values remain explicitly unknown", () => {
  const pe = createBasePe();
  pe.coff.Machine = 0xffff;
  pe.opt.Subsystem = 0xffff;

  const facts = readOverviewFacts(renderPeHeaderPreview(pe));

  assert.deepEqual(facts.slice(0, 2), [["Machine", "Unknown (0xffff)"], ["Subsystem", "Unknown (0xffff)"]]);
});

void test("absent and ROM optional headers do not produce Windows fields", async () => {
  const pe = createBasePe();
  const result = await parseForUi(createPeRomFile());
  assert.equal(result.analyzer, "pe");

  assert.deepEqual(readOverviewFacts(renderPeHeaderPreview({ ...pe, opt: null })), [["Machine", "x86 (I386)"]]);
  assert.doesNotMatch(renderPeHeaderPreview(result.parsed), /Subsystem|ImageBase|DllCharacteristics/);
  assert.match(renderPeHeaderPreview(result.parsed), /AddressOfEntryPoint/);
});
