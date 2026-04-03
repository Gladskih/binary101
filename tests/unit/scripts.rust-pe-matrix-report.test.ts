"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildSummaryMarkdown } from "../../scripts/rustPeMatrix-report.js";
import type { SummaryFile } from "../../scripts/rustPeMatrix-model.js";

const createSummary = (): SummaryFile => ({
  generatedAt: "2026-03-31T00:00:00.000Z",
  outputRoot: "C:\\temp\\binary101-rust-hello-bin\\matrix",
  hostTarget: "x86_64-pc-windows-gnullvm",
  installedRustStdTargets: ["x86_64-pc-windows-gnullvm"],
  attemptedCount: 2,
  successCount: 1,
  failureCount: 1,
  variants: [
    {
      kind: "success",
      id: "core-opt3-dbg0-panicunwind-stripnone-cpugeneric",
      label: "success",
      commandLine: "rustc hello.rs",
      outputPath: "C:\\temp\\ok.exe",
      outputSize: 270848,
      durationMs: 1234,
      analyzer: {
        machine: 0x8664,
        optionalMagic: 0x20b,
        subsystem: 3,
        dllCharacteristics: 0x8160,
        imageBase: "5368709120",
        sectionAlignment: 4096,
        fileAlignment: 512,
        sizeOfImage: 266240,
        sizeOfHeaders: 1024,
        stackReserve: "1048576",
        stackCommit: "4096",
        heapReserve: "1048576",
        heapCommit: "4096",
        entryPointRva: 4096,
        entrySection: ".text",
        dataDirectories: ["IMPORT", "IAT"],
        sectionNames: [".text"],
        warningCount: 0,
        warnings: [],
        debugWarning: null,
        overlaySize: 0,
        trailingAlignmentPaddingSize: 0,
        coffSymbolRecords: 0,
        coffStringTableSize: 0,
        importDllCount: 2,
        importDllNames: ["KERNEL32.dll", "api-ms-win-crt-runtime-l1-1-0.dll"],
        importFunctionCount: 5,
        importFunctionNames: ["KERNEL32.dll!ExitProcess"],
        tlsCallbackCount: 0,
        hasLegacyCoffTailUi: false,
        hasOverlayWarningUi: false,
        sanityCleanUi: true
      }
    },
    {
      kind: "failure",
      id: "cross-aarch64-msvc",
      label: "failure",
      commandLine: "rustc hello.rs --target aarch64-pc-windows-msvc",
      durationMs: 111,
      error: "can't find crate for `std`"
    }
  ]
});

void test("buildSummaryMarkdown includes successful and failed variant tables", () => {
  const markdown = buildSummaryMarkdown(createSummary());

  assert.match(markdown, /Attempted variants: 2/);
  assert.match(markdown, /Successful builds/);
  assert.match(markdown, /core-opt3-dbg0-panicunwind-stripnone-cpugeneric/);
  assert.match(markdown, /Failed builds/);
  assert.match(markdown, /cross-aarch64-msvc/);
});
