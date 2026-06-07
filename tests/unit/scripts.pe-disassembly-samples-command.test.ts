"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createVisualStudioStep, toCommandLine } from "../../scripts/peDisassemblySamples-command.js";
import type { VisualStudioToolchain } from "../../scripts/peDisassemblySamples-model.js";

const createVisualStudio = (): VisualStudioToolchain => ({
  installationPath: "C:\\VS BuildTools",
  vcvarsallPath: "C:\\VS BuildTools\\VC\\Auxiliary\\Build\\vcvarsall.bat"
});

void test("toCommandLine quotes paths with spaces", () => {
  const commandLine = toCommandLine("clang", [
    "C:\\source folder\\hello.c",
    "-o",
    "C:\\output folder\\hello.exe"
  ]);

  assert.equal(commandLine, "clang \"C:\\source folder\\hello.c\" -o \"C:\\output folder\\hello.exe\"");
});

void test("createVisualStudioStep wraps commands in vcvarsall setup", () => {
  const step = createVisualStudioStep("compile", createVisualStudio(), "x64", [
    ["cl.exe", "C:\\source folder\\hello.c", "/Fe:C:\\output folder\\hello.exe"]
  ]);

  assert.equal(step.executable, "cmd.exe");
  assert.deepEqual(step.args.slice(0, 3), ["/d", "/s", "/c"]);
  assert.match(step.display ?? "", /vcvarsall\.bat" x64 >nul/);
  assert.match(step.display ?? "", /cl\.exe "C:\\source folder\\hello\.c"/);
});
