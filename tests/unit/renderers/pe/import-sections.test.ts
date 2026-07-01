"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  PE_DELAY_IMPORTS_PANEL_ID,
  PE_IMPORTS_PANEL_ID,
  renderDelayImportsPanel,
  renderImportsPanel,
  renderImportLinking,
  renderImports,
  renderBoundImports,
  renderDelayImports,
  renderIat
} from "../../../../renderers/pe/import-sections.js";
import {
  createPeWithImportLinking,
  createPeWithInferredEagerIatOnly
} from "../../../fixtures/pe-import-linking-fixture.js";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import type { PeImportMetadataEntry } from "../../../../pe-import-metadata-schema.js";
import type { WinapiMetadataEntry } from "../../../../winapi-metadata-schema.js";

const DIRECT_IAT_REFERENCE_COLUMN_COUNT = 2;
const DIRECT_CALL_REFERENCE_COUNT = 2;
const DIRECT_JUMP_REFERENCE_COUNT = 1;
const NO_DIRECT_IAT_REFERENCES = 0;

const sleepMetadata = (): WinapiMetadataEntry => ({
  sourceKind: "winapi",
  id: "MethodDef:0x06000001;ImplMap:1",
  module: "KERNEL32.dll",
  entrypoint: "Sleep",
  namespace: "Windows.Win32.System.Threading",
  api: "Sleep",
  signature: "void Sleep(u4 dwMilliseconds)",
  returnType: "void",
  rawReturnType: "void",
  parameters: [{
    name: "dwMilliseconds",
    type: "u4",
    rawType: "u4",
    direction: "in",
    x86StackBytes: 4
  }],
  callingConvention: "winapi",
  variadic: false,
  noReturn: false,
  setLastError: false,
  characterSet: null,
  architecture: [],
  platform: ["windows5.1.2600"]
});

const printfMetadata = (): PeImportMetadataEntry => ({
  sourceKind: "ucrt",
  id: "UCRT:ucrtbase.dll:printf",
  module: "ucrtbase.dll",
  entrypoint: "printf",
  namespace: "UCRT.stdio",
  api: "printf",
  signature: "int printf(const char * format, ...)",
  returnType: "int",
  rawReturnType: "int",
  parameters: [{
    name: "format",
    type: "const char *",
    rawType: "const char *",
    direction: "in",
    x86StackBytes: 4
  }],
  callingConvention: "cdecl",
  variadic: true,
  noReturn: false,
  setLastError: false,
  characterSet: null,
  architecture: [],
  platform: []
});

void test("renderImportLinking and related sections surface confirmed and non-canonical import relationships", () => {
  const pe = createPeWithImportLinking();
  pe.imports.entries[0]!.functions[0]!.winapiMetadata = sleepMetadata();
  const out: string[] = [];

  renderImportLinking(pe, out);
  renderImports(pe, out);
  renderBoundImports(pe, out);
  renderDelayImports(pe, out);
  renderIat(pe, out);

  const html = out.join("");
  assert.ok(html.includes("Import linkage"));
  assert.match(html, /<summary[^>]*><b>Import linkage<\/b> - [^<]+<\/summary>/);
  assert.ok(html.includes("Validated checks"));
  assert.ok(html.includes("Warnings"));
  assert.ok(html.includes("IAT fallback / FirstThunk"));
  assert.ok(html.includes("Matched BOUND_IMPORT entry"));
  assert.ok(html.includes("Delay-load IAT is isolated in the canonical .didat section"));
  assert.ok(html.includes("Names come from OriginalFirstThunk / the Import Lookup Table (INT)."));
  assert.ok(!html.includes("normally resolved as a Windows KnownDLL"));
  assert.ok(html.includes("DLL-name note"));
  assert.ok(html.includes("Name-based DLL note"));
  assert.ok(html.includes("Core Win32 file, process, thread, memory"));
  assert.ok(html.includes("Window manager, message, input, menu, dialog"));
  assert.ok(html.includes("<td>Sleep</td>"));
  assert.ok(html.includes("<td>MessageBoxW</td>"));
  assert.ok(html.includes("<th>API</th>"));
  assert.ok(html.includes("Windows.Win32.System.Threading"));
  assert.ok(html.includes("void Sleep(u4 dwMilliseconds)"));
  assert.ok(!html.includes("learn.microsoft.com/search"));
  assert.ok(
    html.includes(
      "Import descriptor TimeDateStamp is non-zero, but no matching BOUND_IMPORT entry was found."
    )
  );
  assert.ok(html.includes("Load Config delay-IAT flags"));
  assert.ok(html.includes("Protected delay-load modules"));
  assert.ok(html.includes("Bound import entry without a matching eager import descriptor."));
  assert.ok(html.includes("Declared vs inferred eager IAT"));
  assert.ok(html.includes("Declared IAT covers all inferred eager IAT ranges"));
  assert.match(html, /<summary[^>]*><b>Import Address Tables \(IAT\)<\/b> - [^<]+<\/summary>/);
  assert.ok(html.includes("Descriptors"));
  assert.ok(!html.includes("Show linked modules"));
  assert.ok(!html.includes("Show bound imports"));
  assert.ok(!html.includes("Show inferred eager IAT ranges"));
});

void test("renderImports shows UCRT import metadata from generic API enrichment", () => {
  const pe = createPeWithImportLinking();
  pe.imports.entries[0]!.dll = "ucrtbase.dll";
  pe.imports.entries[0]!.functions = [{ hint: 1, name: "printf", apiMetadata: printfMetadata() }];
  const out: string[] = [];

  renderImports(pe, out);

  const html = out.join("");
  assert.ok(html.includes("UCRT.stdio"));
  assert.ok(html.includes("int printf(const char * format, ...)"));
  assert.ok(html.includes("UCRT - cdecl, variadic"));
});

void test("renderImports surfaces warning-only parse results", () => {
  const pe = createPeWithImportLinking();
  pe.imports = {
    thunkEntrySize: pe.imports.thunkEntrySize,
    entries: [],
    warning: "Import directory is smaller than one descriptor; file may be truncated."
  };
  const out: string[] = [];

  renderImports(pe, out);

  const html = out.join("");
  assert.ok(html.includes("Import table"));
  assert.ok(html.includes("file may be truncated"));
});

void test("renderIat shows inferred eager IAT ranges even when IMAGE_DIRECTORY_ENTRY_IAT is absent", () => {
  const pe = createPeWithInferredEagerIatOnly();
  const out: string[] = [];

  renderIat(pe, out);

  const html = out.join("");
  assert.ok(html.includes("Import Address Tables (IAT)"));
  assert.ok(html.includes("Declared IAT directory"));
  assert.ok(html.includes("Absent"));
  assert.ok(html.includes("Inferred eager IAT ranges"));
  assert.ok(
    html.includes(
      "IMAGE_DIRECTORY_ENTRY_IAT is absent, but eager IAT ranges were inferred from FirstThunk values in the import descriptors."
    )
  );
});

void test("renderIat displays declared IAT directory warnings", () => {
  const pe = createPeWithImportLinking();
  pe.iat = {
    ...pe.iat!,
    warnings: ["IAT directory RVA could not be mapped to a file offset."]
  };
  const out: string[] = [];

  renderIat(pe, out);

  const html = out.join("");
  assert.match(html, /<summary[^>]*><b>Import Address Tables \(IAT\)<\/b> - [^<]+<\/summary>/);
  assert.ok(html.includes("IAT directory RVA could not be mapped to a file offset."));
});

void test("renderBoundImports surfaces warning-only parse results", () => {
  const pe = {
    boundImports: {
      entries: [],
      warning: "Bound import directory is smaller than one descriptor; file may be truncated."
    }
  } as unknown as PeWindowsParseResult;
  const out: string[] = [];

  renderBoundImports(pe, out);

  const html = out.join("");
  assert.ok(html.includes("Bound imports"));
  assert.ok(html.includes("file may be truncated"));
});

void test("renderDelayImports surfaces warning-only parse results", () => {
  const pe = {
    delayImports: {
      entries: [],
      warning: "Delay import directory is smaller than one descriptor; file may be truncated."
    }
  } as unknown as PeWindowsParseResult;
  const out: string[] = [];

  renderDelayImports(pe, out);

  const html = out.join("");
  assert.ok(html.includes("Delay-load imports"));
  assert.ok(html.includes("file may be truncated"));
});

void test("import panels render separate call and jump counters from the disassembly model", () => {
  const pe = createPeWithImportLinking();
  const eagerIatSlotRva = pe.imports.entries[0]!.firstThunkRva;
  const delayIatSlotRva = pe.delayImports!.entries[0]!.ImportAddressTableRVA;
  pe.disassembly = {
    bitness: 32,
    bytesSampled: 16,
    bytesDecoded: 16,
    instructionCount: 4,
    invalidInstructionCount: 0,
    directIatReferences: [
      {
        slotRva: eagerIatSlotRva,
        callReferenceCount: DIRECT_CALL_REFERENCE_COUNT,
        jumpReferenceCount: NO_DIRECT_IAT_REFERENCES
      },
      {
        slotRva: delayIatSlotRva,
        callReferenceCount: NO_DIRECT_IAT_REFERENCES,
        jumpReferenceCount: DIRECT_JUMP_REFERENCE_COUNT
      }
    ],
    codeStringReferences: [],
    apiStringReferences: [],
    instructionSets: [],
    issues: []
  };

  const importsHtml = renderImportsPanel(pe);
  const delayHtml = renderDelayImportsPanel(pe);

  assert.ok(importsHtml.includes(`id="${PE_IMPORTS_PANEL_ID}"`));
  assert.ok(delayHtml.includes(`id="${PE_DELAY_IMPORTS_PANEL_ID}"`));
  assert.match(importsHtml, /Direct CALL refs/);
  assert.match(importsHtml, /Direct JMP refs/);
  assert.match(
    importsHtml,
    new RegExp(`data-sort-value="${DIRECT_CALL_REFERENCE_COUNT}">` +
      `${DIRECT_CALL_REFERENCE_COUNT}</td>`)
  );
  assert.match(importsHtml, /data-sort-value="0">—<\/td>/);
  assert.match(
    delayHtml,
    new RegExp(`data-sort-value="${DIRECT_JUMP_REFERENCE_COUNT}">` +
      `${DIRECT_JUMP_REFERENCE_COUNT}</td>`)
  );
  assert.match(importsHtml, /data-accessible-tooltip/);
});

void test("import panels render dashes before Instruction-set, imports and strings analysis", () => {
  const pe = createPeWithImportLinking();

  const importsHtml = renderImportsPanel(pe);
  const delayHtml = renderDelayImportsPanel(pe);

  assert.equal(
    (importsHtml.match(/data-sort-value="0">—<\/td>/g) ?? []).length,
    pe.imports.entries.flatMap(entry => entry.functions).length * DIRECT_IAT_REFERENCE_COLUMN_COUNT
  );
  assert.equal(
    (delayHtml.match(/data-sort-value="0">—<\/td>/g) ?? []).length,
    (pe.delayImports?.entries.flatMap(entry => entry.functions).length ?? 0) *
      DIRECT_IAT_REFERENCE_COLUMN_COUNT
  );
});
