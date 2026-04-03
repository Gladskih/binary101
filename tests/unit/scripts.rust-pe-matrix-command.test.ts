"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { toCommandLine, toRustcArgs } from "../../scripts/rustPeMatrix-command.js";
import type { VariantSpec } from "../../scripts/rustPeMatrix-model.js";

const createVariant = (): VariantSpec => ({
  id: "demo",
  label: "demo variant",
  sourceFile: "hello.rs",
  target: "x86_64-pc-windows-gnullvm",
  rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0"]
});

void test("toRustcArgs places target and output before rustc codegen flags", () => {
  const args = toRustcArgs("C:\\temp\\hello.rs", "C:\\temp\\demo.exe", createVariant());

  assert.deepEqual(args, [
    "C:\\temp\\hello.rs",
    "--target",
    "x86_64-pc-windows-gnullvm",
    "-o",
    "C:\\temp\\demo.exe",
    "-C",
    "opt-level=3",
    "-C",
    "debuginfo=0"
  ]);
});

void test("toCommandLine quotes paths with spaces and escaped quotes", () => {
  const commandLine = toCommandLine("rustc", [
    "C:\\Temp Folder\\hello.rs",
    "-o",
    "C:\\Temp Folder\\demo \"quoted\".exe"
  ]);

  assert.equal(
    commandLine,
    "rustc \"C:\\Temp Folder\\hello.rs\" -o " +
      "\"C:\\Temp Folder\\demo \\\"quoted\\\".exe\""
  );
});
