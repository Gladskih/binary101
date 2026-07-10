"use strict";

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../analyzers/pe/index.js";
import type { MsvcRttiAnalysis } from "../../analyzers/pe/msvc-rtti/types.js";
import {
  createVisualStudioStep,
  runStep
} from "../../scripts/pe-disassembly-samples/command.js";
import {
  sampleSourceRoot,
  type VisualStudioToolchain
} from "../../scripts/pe-disassembly-samples/model.js";
import { discoverToolchains } from "../../scripts/pe-disassembly-samples/toolchains.js";

const buildFixture = async (
  directory: string,
  visualStudio: VisualStudioToolchain
): Promise<string> => {
  const executablePath = join(directory, "msvc-rtti.exe");
  const step = createVisualStudioStep("compile", visualStudio, "x64", [[
    "cl.exe",
    join(sampleSourceRoot, "cpp", "msvc-rtti.cpp"),
    "/nologo",
    "/std:c++20",
    "/O2",
    "/GR",
    "/EHsc",
    "/MD",
    `/Fo:${join(directory, "msvc-rtti.obj")}`,
    `/Fe:${executablePath}`,
    "/link",
    "/DYNAMICBASE",
    "/FIXED:NO",
    "/INCREMENTAL:NO",
    "/OPT:REF",
    "/OPT:ICF"
  ]]);
  const result = await runStep(step);
  assert.equal(
    result.code,
    0,
    [result.stdout, result.stderr].filter(Boolean).join("\n") || "MSVC fixture build failed."
  );
  return executablePath;
};

const assertExpectedRtti = (analysis: MsvcRttiAnalysis): void => {
  assert.equal(analysis.layout, "microsoft-cxx-amd64-image-relative-rtti-rev1");
  const typesByName = new Map(analysis.types.map(type => [type.decoratedName, type]));
  for (const decoratedName of [
    ".?AVSimpleBase@Binary101RttiFixture@@",
    ".?AVSingleDerived@Binary101RttiFixture@@",
    ".?AVLeftBase@Binary101RttiFixture@@",
    ".?AVRightBase@Binary101RttiFixture@@",
    ".?AVMultipleDerived@Binary101RttiFixture@@",
    ".?AVVirtualBase@Binary101RttiFixture@@",
    ".?AVVirtualLeft@Binary101RttiFixture@@",
    ".?AVVirtualRight@Binary101RttiFixture@@",
    ".?AVVirtualDiamond@Binary101RttiFixture@@"
  ]) {
    assert.ok(typesByName.has(decoratedName), `Missing RTTI type ${decoratedName}`);
  }
  const multipleType = typesByName.get(".?AVMultipleDerived@Binary101RttiFixture@@");
  assert.ok(multipleType);
  const multipleLocators = analysis.completeObjectLocators.filter(
    locator => locator.typeDescriptorRva === multipleType.rva
  );
  assert.ok(multipleLocators.length >= 2);
  const multipleLocatorRvas = new Set(multipleLocators.map(locator => locator.rva));
  assert.ok(analysis.vftables.filter(
    vftable => multipleLocatorRvas.has(vftable.completeObjectLocatorRva)
  ).length >= 2);
  assert.ok(analysis.vftables.every(vftable => vftable.functionTargetRvas.length > 0));
  assert.ok(analysis.vftables.flatMap(
    vftable => vftable.functionTargetRvas
  ).every(targetRva => targetRva > 0));
};

void test("MSVC x64 RTTI is found in an optimized relocation-backed PE", async context => {
  if (process.platform !== "win32") return context.skip("MSVC fixture requires Windows.");
  const visualStudio = (await discoverToolchains()).visualStudio;
  if (!visualStudio) return context.skip("Visual Studio C++ Build Tools are not installed.");
  const directory = await mkdtemp(join(tmpdir(), "binary101-msvc-rtti-"));
  try {
    const executablePath = await buildFixture(directory, visualStudio);
    const bytes = await readFile(executablePath);
    const parsed = await parsePe(new File([bytes], "msvc-rtti.exe"));

    assert.ok(parsed && isPeWindowsParseResult(parsed));
    assert.equal(parsed.coff.PointerToSymbolTable, 0);
    assert.equal(parsed.coff.NumberOfSymbols, 0);
    assert.ok(parsed.reloc && parsed.reloc.totalEntries > 0);
    assert.ok(parsed.msvcRtti);
    assertExpectedRtti(parsed.msvcRtti);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
