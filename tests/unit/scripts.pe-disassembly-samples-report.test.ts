"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildSummary, buildSummaryMarkdown } from "../../scripts/peDisassemblySamples-report.js";
import type { SampleResult } from "../../scripts/peDisassemblySamples-model.js";

const createResults = (): SampleResult[] => [
  {
    kind: "success",
    id: "c-msvc-x64-o2-md",
    label: "x64 O2 /MD",
    language: "c",
    outputPath: "C:\\out\\hello.exe",
    outputSize: 4096,
    durationMs: 100,
    commandLines: ["cl hello.c"],
    steps: [{ code: 0, durationMs: 100, label: "compile", stdout: "", stderr: "" }]
  },
  {
    kind: "failure",
    id: "zig-x64-debug",
    label: "zig debug",
    language: "zig",
    durationMs: 50,
    commandLines: ["zig build-exe hello.zig"],
    error: "compiler failed\nsecond line",
    steps: [{ code: 1, durationMs: 50, label: "compile", stdout: "", stderr: "compiler failed" }]
  },
  {
    kind: "skipped",
    id: "assembly-nasm-x64-lld",
    label: "nasm",
    language: "assembly",
    commandLines: [],
    reason: "nasm was not found."
  }
];

void test("buildSummary counts sample outcomes", () => {
  const summary = buildSummary("C:\\out", createResults());

  assert.equal(summary.attemptedCount, 3);
  assert.equal(summary.successCount, 1);
  assert.equal(summary.failureCount, 1);
  assert.equal(summary.skippedCount, 1);
});

void test("buildSummaryMarkdown renders success failure and skipped tables", () => {
  const markdown = buildSummaryMarkdown(buildSummary("C:\\out", createResults()));

  assert.match(markdown, /Successful builds/);
  assert.match(markdown, /c-msvc-x64-o2-md/);
  assert.match(markdown, /Failed builds/);
  assert.match(markdown, /compiler failed second line/);
  assert.match(markdown, /Skipped builds/);
  assert.match(markdown, /assembly-nasm-x64-lld/);
});
