"use strict";

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { test } from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../analyzers/pe/index.js";

const run = promisify(execFile);

const hasGo = async (): Promise<boolean> => {
  try {
    await run("go", ["version"]);
    return true;
  } catch {
    return false;
  }
};

const parseBuiltGoPe = async (directory: string, name: string, linkerFlags?: string) => {
  const args = ["build"];
  if (linkerFlags) args.push("-ldflags", linkerFlags);
  args.push("-o", name, "hello.go");
  await run("go", args, { cwd: directory });
  const bytes = await readFile(join(directory, name));
  return parsePe(new File([bytes], name));
};

void test("Go PE runtime metadata survives normal and fully stripped builds", async context => {
  if (!(await hasGo())) return context.skip("Go toolchain is not installed");
  const directory = await mkdtemp(join(tmpdir(), "binary101-go-runtime-"));
  try {
    await writeFile(join(directory, "hello.go"), "package main\nfunc main() { println(\"hello\") }\n");

    const normal = await parseBuiltGoPe(directory, "hello.exe");
    const stripped = await parseBuiltGoPe(directory, "hello-stripped.exe", "-s -w");

    assert.ok(normal && isPeWindowsParseResult(normal));
    assert.ok(stripped && isPeWindowsParseResult(stripped));
    for (const parsed of [normal, stripped]) {
      assert.equal(parsed.goRuntime?.layout, "go1.20+");
      assert.ok(parsed.goRuntime.functions.length > 1000);
      assert.ok(parsed.goRuntime.fileCount > 100);
      assert.ok(parsed.goRuntime.functions.some(fn => fn.name === "main.main"));
      assert.ok(parsed.goRuntime.functions.every(fn => fn.start < fn.end));
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
