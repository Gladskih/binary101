"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  renderReloc,
  renderException,
  renderBoundImports,
  renderDelayImports,
  renderCoverage,
  renderSanity
} from "../../renderers/pe/layout.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

const emptyPe = {} as PeParseResult;

void test("layout renderers skip when data is missing", () => {
  const out: string[] = [];
  renderReloc(emptyPe, out);
  renderException(emptyPe, out);
  renderBoundImports(emptyPe, out);
  renderDelayImports(emptyPe, out);
  renderCoverage(emptyPe, out);
  assert.strictEqual(out.length, 0);
});

void test("renderReloc wraps relocation table in details", () => {
  const pe = {
    reloc: { totalEntries: 3, blocks: [{ pageRva: 0x1000, size: 12, count: 1 }] }
  } as unknown as PeParseResult;
  const out: string[] = [];
  renderReloc(pe, out);
  const html = out.join("");
  assert.ok(html.includes("Show blocks (1)"));
});

void test("renderException renders pdata stats", () => {
  const pe = {
    exception: {
      functionCount: 1,
      beginRvas: [0x1000],
      uniqueUnwindInfoCount: 1,
      handlerUnwindInfoCount: 1,
      chainedUnwindInfoCount: 0,
      invalidEntryCount: 0,
      issues: []
    }
  } as unknown as PeParseResult;
  const out: string[] = [];
  renderException(pe, out);
  const html = out.join("");
  assert.ok(html.includes("Functions (RUNTIME_FUNCTION entries)"));
  assert.ok(html.includes("<dd>1</dd>"));
  assert.ok(html.includes("Unique UNWIND_INFO blocks"));
  assert.ok(html.includes("Handlers present (EHANDLER/UHANDLER)"));
  assert.ok(html.includes("Chained (CHAININFO)"));
  assert.ok(html.includes("Missing/invalid ranges"));
  assert.ok(!html.includes("Show unwind entries"));
});

void test("renderBoundImports renders warning and details table", () => {
  const pe = {
    boundImports: {
      warning: "synthetic warning",
      entries: [{ name: "a.dll", TimeDateStamp: 0, NumberOfModuleForwarderRefs: 0 }]
    }
  } as unknown as PeParseResult;
  const out: string[] = [];
  renderBoundImports(pe, out);
  const html = out.join("");
  assert.ok(html.includes("synthetic warning"));
  assert.ok(html.includes("Show bound imports (1)"));
});

void test("renderDelayImports renders function names and ordinals", () => {
  const pe = {
    delayImports: {
      warning: "delay warning",
      entries: [
        {
          name: "KERNEL32.dll",
          Attributes: 1,
          ModuleHandleRVA: 0,
          ImportAddressTableRVA: 0,
          ImportNameTableRVA: 0,
          BoundImportAddressTableRVA: 0,
          UnloadInformationTableRVA: 0,
          TimeDateStamp: 0,
          functions: [{ hint: 0, name: "Foo" }, { hint: 1, ordinal: 5 }, {}]
        }
      ]
    }
  } as unknown as PeParseResult;
  const out: string[] = [];
  renderDelayImports(pe, out);
  const html = out.join("");
  assert.ok(html.includes("delay warning"));
  assert.ok(html.includes("Foo"));
  assert.ok(html.includes("ORD 5"));
});

void test("renderCoverage wraps coverage table in details", () => {
  const pe = {
    coverage: [{ label: "Headers", off: 0, size: 64 }]
  } as unknown as PeParseResult;
  const out: string[] = [];
  renderCoverage(pe, out);
  const html = out.join("");
  assert.ok(html.includes("Show coverage segments (1)"));
});

void test("renderSanity renders issues and clean state", () => {
  const withIssues = {
    overlaySize: 100,
    imageSizeMismatch: true,
    debugWarning: "bad debug"
  } as unknown as PeParseResult;
  const outIssues: string[] = [];
  renderSanity(withIssues, outIssues);
  const htmlIssues = outIssues.join("");
  assert.ok(htmlIssues.includes("Overlay after last section"));
  assert.ok(htmlIssues.includes("SizeOfImage does not match"));
  assert.ok(htmlIssues.includes("bad debug"));

  const clean = {
    overlaySize: 0,
    imageSizeMismatch: false,
    debugWarning: null
  } as unknown as PeParseResult;
  const outClean: string[] = [];
  renderSanity(clean, outClean);
  assert.ok(outClean.join("").includes("No obvious structural issues"));
});

void test("renderSanity reports suspicious entrypoint sections", () => {
  const outside = {
    overlaySize: 0,
    imageSizeMismatch: false,
    debugWarning: null,
    opt: { AddressOfEntryPoint: 0x3000 },
    sections: [
      {
        name: ".text",
        virtualSize: 0x100,
        virtualAddress: 0x1000,
        sizeOfRawData: 0x100,
        pointerToRawData: 0,
        characteristics: 0x60000020
      }
    ]
  } as unknown as PeParseResult;

  const outOutside: string[] = [];
  renderSanity(outside, outOutside);
  assert.ok(outOutside.join("").includes("AddressOfEntryPoint points outside any section"));

  const nonExecutable = {
    overlaySize: 0,
    imageSizeMismatch: false,
    debugWarning: null,
    opt: { AddressOfEntryPoint: 0x2000 },
    sections: [
      {
        name: ".data",
        virtualSize: 0x100,
        virtualAddress: 0x2000,
        sizeOfRawData: 0x100,
        pointerToRawData: 0,
        characteristics: 0x40000040
      }
    ]
  } as unknown as PeParseResult;

  const outNonExecutable: string[] = [];
  renderSanity(nonExecutable, outNonExecutable);
  assert.ok(outNonExecutable.join("").includes("missing IMAGE_SCN_MEM_EXECUTE"));
});
