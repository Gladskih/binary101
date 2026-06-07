"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  BinarySizeTableColumns,
  SampleSummary,
  SuccessfulSampleResult
} from "../../../../scripts/pe-disassembly-samples/model.js";
import { buildBinarySizeMarkdown } from "../../../../scripts/pe-disassembly-samples/size-table.js";

const createSuccess = (
  id: string,
  language: SuccessfulSampleResult["language"],
  outputSize: number,
  sizeTableColumns: BinarySizeTableColumns
): SuccessfulSampleResult => ({
  kind: "success",
  id,
  label: id,
  language,
  sizeTableColumns,
  outputPath: `C:\\out\\${id}.exe`,
  outputSize,
  durationMs: 1,
  commandLines: [],
  steps: []
});

const createSummary = (): SampleSummary => ({
  generatedAt: "2026-06-07T00:00:00.000Z",
  outputRoot: "C:\\out",
  attemptedCount: 3,
  successCount: 3,
  failureCount: 0,
  skippedCount: 0,
  results: [
    createSuccess("c-msys-ucrt64-x64-o2", "c", 17920, {
      arch: "x64",
      compiler: "MSYS2 UCRT64 GCC/G++",
      mode: "o2",
      runtimeLinkage: "MSYS2 UCRT DLLs"
    }),
    createSuccess("rust-x64-msvc-o3-panic-abort", "rust", 123904, {
      arch: "x64",
      compiler: "rustc MSVC",
      mode: "o3-panic-abort",
      runtimeLinkage: "Rust std static + MSVC/UCRT DLLs"
    }),
    createSuccess("csharp-readytorun-singlefile-win-x64-release", "csharp", 180914, {
      arch: "x64",
      compiler: ".NET publish",
      mode: "readytorun singlefile release",
      runtimeLinkage: ".NET runtime external single-file"
    })
  ]
});

void test("buildBinarySizeMarkdown renders generated comparison columns", () => {
  const markdown = buildBinarySizeMarkdown(createSummary());

  assert.match(markdown, /The build pipeline validates primary PE outputs/);
  assert.match(markdown, /Those outputs should have no COFF symbol records/);
  assert.match(markdown, /Go internal linker may leave an empty COFF pointer/);
  assert.match(markdown, /\| c \| x64 \| MSYS2 UCRT64 GCC\/G\+\+ \| o2 \| MSYS2 UCRT DLLs \| 17920 \| 17\.5 \|/);
  assert.match(markdown, /\| rust \| x64 \| rustc MSVC \| o3-panic-abort \| Rust std static \+ MSVC\/UCRT DLLs \|/);
  assert.match(markdown, /\| csharp \| x64 \| \.NET publish \| readytorun singlefile release \|/);
});
