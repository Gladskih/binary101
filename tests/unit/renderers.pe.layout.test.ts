"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  renderReloc,
  renderException,
  renderBoundImports,
  renderDelayImports,
  renderSanity
} from "../../renderers/pe/layout.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

void test("renderReloc wraps relocation table in details", () => {
  const reloc: Parameters<typeof renderReloc>[0] = {
    totalEntries: 3,
    blocks: [{ pageRva: 0x1000, size: 12, count: 1, entries: [] }]
  };
  const out: string[] = [];
  renderReloc(reloc, out);
  const html = out.join("");
  assert.ok(html.includes("Show blocks (1)"));
});

void test("renderException renders pdata stats", () => {
  const exception: Parameters<typeof renderException>[0] = {
    functionCount: 1,
    beginRvas: [0x1000],
    handlerRvas: [],
    uniqueUnwindInfoCount: 1,
    handlerUnwindInfoCount: 1,
    chainedUnwindInfoCount: 0,
    invalidEntryCount: 0,
    issues: []
  };
  const out: string[] = [];
  renderException(exception, out);
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
  const boundImports: Parameters<typeof renderBoundImports>[0] = {
    warning: "synthetic warning",
    entries: [{ name: "a.dll", TimeDateStamp: 0, NumberOfModuleForwarderRefs: 0 }]
  };
  const out: string[] = [];
  renderBoundImports(boundImports, out);
  const html = out.join("");
  assert.ok(html.includes("synthetic warning"));
  assert.ok(html.includes("Show bound imports (1)"));
});

void test("renderDelayImports renders function names and ordinals", () => {
  const delayImports: Parameters<typeof renderDelayImports>[0] = {
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
  };
  const out: string[] = [];
  renderDelayImports(delayImports, out);
  const html = out.join("");
  assert.ok(html.includes("delay warning"));
  assert.ok(html.includes("Foo"));
  assert.ok(html.includes("ORD 5"));
  assert.ok(html.includes("dlattrRva"));
  assert.ok(html.includes("PE format page"));
  assert.ok(html.includes("delayimp.h"));
});

void test("renderSanity renders issues and clean state", () => {
  const withIssues = {
    overlaySize: 100,
    imageSizeMismatch: true,
    debug: { entry: null, warning: "bad debug" }
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
    debug: null
  } as unknown as PeParseResult;
  const outClean: string[] = [];
  renderSanity(clean, outClean);
  assert.ok(outClean.join("").includes("No obvious structural issues"));
});

void test("renderSanity reports suspicious entrypoint sections", () => {
  const outside = {
    overlaySize: 0,
    imageSizeMismatch: false,
    debug: null,
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
    debug: null,
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

void test("renderSanity treats raw padding beyond VirtualSize as outside the mapped section", () => {
  const sectionVirtualAddress = 0x1000;
  const sectionVirtualSize = 0x100;
  const sectionRawSize = 0x200;
  const pe = {
    overlaySize: 0,
    imageSizeMismatch: false,
    debug: null,
    // Place the entrypoint inside the on-disk raw padding, halfway between VirtualSize and SizeOfRawData.
    opt: {
      AddressOfEntryPoint:
        sectionVirtualAddress + sectionVirtualSize + (sectionRawSize - sectionVirtualSize) / 2
    },
    sections: [
      {
        name: ".text",
        // Microsoft PE format: if SizeOfRawData exceeds VirtualSize, the extra on-disk bytes are not mapped.
        virtualSize: sectionVirtualSize,
        virtualAddress: sectionVirtualAddress,
        sizeOfRawData: sectionRawSize,
        pointerToRawData: 0x200,
        characteristics: 0x60000020
      }
    ]
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderSanity(pe, out);
  assert.ok(out.join("").includes("AddressOfEntryPoint points outside any section"));
});

void test("renderSanity does not flag certificate table bytes as suspicious overlay", () => {
  const pe = {
    overlaySize: 0x20,
    imageSizeMismatch: false,
    debug: null,
    dirs: [{ name: "SECURITY", rva: 0x400, size: 0x20 }],
    sections: [
      {
        name: ".text",
        virtualSize: 0x200,
        virtualAddress: 0x1000,
        sizeOfRawData: 0x200,
        pointerToRawData: 0x200,
        characteristics: 0x60000020
      }
    ],
    opt: { AddressOfEntryPoint: 0x1000 }
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderSanity(pe, out);
  const html = out.join("");
  assert.ok(!html.includes("Overlay after last section"));
  assert.ok(html.includes("No obvious structural issues"));
});

void test("renderSanity skips SizeOfImage mismatch warnings for ROM images", () => {
  const pe = {
    overlaySize: 0,
    imageSizeMismatch: true,
    debug: null,
    opt: { Magic: 0x107 }
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderSanity(pe, out);

  assert.ok(!out.join("").includes("SizeOfImage does not match"));
});

void test("renderSanity still reports unexplained overlay after certificate table", () => {
  const pe = {
    overlaySize: 0x40,
    imageSizeMismatch: false,
    debug: null,
    dirs: [{ name: "SECURITY", rva: 0x420, size: 0x20 }],
    sections: [
      {
        name: ".text",
        virtualSize: 0x200,
        virtualAddress: 0x1000,
        sizeOfRawData: 0x200,
        pointerToRawData: 0x200,
        characteristics: 0x60000020
      }
    ],
    opt: { AddressOfEntryPoint: 0x1000 }
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderSanity(pe, out);
  assert.ok(out.join("").includes("Overlay after last section"));
});

void test("renderSanity does not flag debug raw data after certificates as unexplained overlay", () => {
  const pe = {
    overlaySize: 0x3a,
    imageSizeMismatch: false,
    debug: {
      entry: { guid: "g", age: 1, path: "a.pdb" },
      rawDataRanges: [{ start: 0x420, end: 0x43a }]
    },
    dirs: [{ name: "SECURITY", rva: 0x400, size: 0x20 }],
    sections: [
      {
        name: ".text",
        virtualSize: 0x200,
        virtualAddress: 0x1000,
        sizeOfRawData: 0x200,
        pointerToRawData: 0x200,
        characteristics: 0x60000020
      }
    ],
    opt: { AddressOfEntryPoint: 0x1000 }
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderSanity(pe, out);
  assert.ok(!out.join("").includes("Overlay after last section"));
});
