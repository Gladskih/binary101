import assert from "node:assert/strict";
import { test } from "node:test";
import { withPeMsvcEh } from "../../../../../analyzers/pe/msvc-eh/pe.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { parsePeHeaders, isPeWindowsCore } from "../../../../../analyzers/pe/core/index.js";
import { createPeLoadConfigResult } from "../../../../../analyzers/pe/load-config/result.js";
import { createEhFixture, addFh4, buildEhPeImage } from "../../../../fixtures/pe-msvc-eh.js";
import type { CoffDebugInfo } from "../../../../../analyzers/coff/debug-types.js";
import type { PeLegacyCodeViewInfo } from "../../../../../analyzers/pe/debug/legacy-codeview.js";
import type { PeWindowsParseResult } from "../../../../../analyzers/pe/core/parse-result.js";

const fixturePe = async () => {
  const subject = createEhFixture();
  addFh4(subject);
  const file = buildEhPeImage(subject);
  const pe = await parsePe(file);
  const core = await parsePeHeaders(file);
  assert.ok(pe && isPeWindowsParseResult(pe) && core && isPeWindowsCore(core));
  return { file, pe, core };
};

const symbolPe = async () => {
  const subject = await fixturePe();
  const offset = subject.pe.exception!.languageHandlers![0]!.handlerRva - subject.core.sections[0]!.virtualAddress;
  const coff: CoffDebugInfo = { source: "coff-header", symbolTableOffset: 0, stringTableOffset: null,
    lineNumberBlocks: [], symbols: [{ index: 0, name: "__GSHandlerCheck_EH4", nameSource: "short",
      value: offset, sectionNumber: 1, type: 0x20, storageClass: 2, auxiliarySymbolCount: 0,
      auxiliaryRecords: [] }] };
  const codeview: PeLegacyCodeViewInfo = { signature: "NB09", directories: [{ flags: 0, subsections: [
    { type: 0x124, module: 1, offset: 0, size: 40, data: { kind: "symbols", records: [
      { type: 0x1110, name: "__GSHandlerCheck_EH4", procedure: { referenceKind: "typeIndex",
        codeLength: 16, storedLocation: { segment: 1, offset } } }
    ] } }
  ] }] };
  return { ...subject, pe: { ...subject.pe, imports: { ...subject.pe.imports, entries: [] } }, coff, codeview };
};

void test("PE EH integration appends cross-checks to Load Config without losing existing checks", async () => {
  const { file, pe, core } = await fixturePe();
  const loadcfg = createPeLoadConfigResult();
  loadcfg.Size = 0x118;
  loadcfg.GuardFlags = 0x00400000;
  loadcfg.checks = [{ status: "info", title: "existing", detail: "existing" }];
  const parsed = await withPeMsvcEh(file, core, { ...pe, loadcfg });
  assert.equal(parsed.loadcfg?.checks?.[0]?.title, "existing");
  assert.equal(parsed.loadcfg?.checks?.[1]?.status, "fail");
  assert.deepEqual(parsed.msvcEh?.warnings, []);
});

void test("NO_SEH is reported with EH when no Load Config owns the check", async () => {
  const { file, pe, core } = await fixturePe();
  pe.opt.DllCharacteristics |= 0x0400;
  const parsed = await withPeMsvcEh(file, core, pe);
  assert.match(parsed.msvcEh?.warnings[0] ?? "", /NO_SEH/);
});

void test("an unrelated image remains unchanged by optional EH enrichment", async () => {
  const { file, pe, core } = await fixturePe();
  core.coff.Machine = 0x5032; // RISC-V is outside supported MSVC EH layouts.
  assert.equal(await withPeMsvcEh(file, core, pe), pe);
});

void test("PE-header COFF symbols independently establish an otherwise unnamed FH4 personality", async () => {
  const { file, pe, core, coff } = await symbolPe();
  const parsed = await withPeMsvcEh(file, core, { ...pe, coffDebug: coff });
  assert.equal(parsed.msvcEh?.records[0]?.functionInfo?.version, 4);
  assert.match(parsed.msvcEh?.records[0]?.evidence ?? "", /COFF/);
});

void test("debug-directory COFF symbols reach EH identity", async () => {
  const { file, pe, core, coff } = await symbolPe();
  pe.debug = { entry: null, entries: [{ type: 1, coff }] } as PeWindowsParseResult["debug"];
  assert.equal((await withPeMsvcEh(file, core, pe)).msvcEh?.records[0]?.functionInfo?.version, 4);
});

void test("debug-directory CodeView procedures reach EH identity", async () => {
  const { file, pe, core, codeview } = await symbolPe();
  pe.debug = { entry: null, entries: [{ type: 2, legacyCodeView: codeview }] } as PeWindowsParseResult["debug"];
  assert.equal((await withPeMsvcEh(file, core, pe)).msvcEh?.records[0]?.functionInfo?.version, 4);
});

void test("additional CodeView source procedures reach EH identity", async () => {
  const { file, pe, core, codeview } = await symbolPe();
  pe.debug = { entry: null, entries: [],
    codeViewSources: [{ kind: "section", offset: 0, size: 40, legacyCodeView: codeview }] };
  assert.equal((await withPeMsvcEh(file, core, pe)).msvcEh?.records[0]?.functionInfo?.version, 4);
});
