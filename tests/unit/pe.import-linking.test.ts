"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeImportLinking } from "../../analyzers/pe/imports/linking.js";
import { expectDefined } from "../helpers/expect-defined.js";
import {
  createImportLinkingInputs,
  createImportLinkingMainSectionOnly,
  createImportLinkingOutsideDirectoryInputs,
  createImportLinkingOwnSectionMismatchInputs,
  createImportLinkingProtectedSeparateSectionInputs,
  createImportLinkingSections
} from "../fixtures/pe-import-linking-fixture.js";

void test("analyzeImportLinking correlates eager, bound, delay, IAT, sections, and Load Config", () => {
  const { imports, boundImports, delayImports, iat, loadcfg } = createImportLinkingInputs();

  const result = expectDefined(
    analyzeImportLinking(
      imports,
      boundImports,
      delayImports,
      iat,
      loadcfg,
      createImportLinkingSections()
    )
  );

  assert.equal(result.modules.length, 3);
  assert.equal(result.inferredEagerIat?.relationToDeclared, "declared-covers-inferred");
  assert.ok(
    result.findings?.some(finding => finding.code === "declared-iat-covers-inferred-eager")
  );

  const kernelModule = expectDefined(result.modules.find(module => module.moduleKey === "kernel32.dll"));
  assert.equal(kernelModule.imports.length, 1);
  assert.equal(kernelModule.boundImports.length, 1);
  assert.deepEqual(kernelModule.imports[0], {
    importIndex: 0,
    iatDirectoryRelation: "covered",
    bindingRelation: "bound-directory-match"
  });
  assert.ok(kernelModule.findings?.some(finding => finding.code === "bound-match"));
  assert.ok(kernelModule.findings?.some(finding => finding.code === "int-lookup"));
  assert.ok(kernelModule.findings?.some(finding => finding.code === "eager-iat-covered"));

  const userModule = expectDefined(result.modules.find(module => module.moduleKey === "user32.dll"));
  assert.equal(userModule.imports.length, 1);
  assert.equal(userModule.delayImports.length, 1);
  assert.ok(userModule.findings?.some(finding => finding.code === "iat-fallback"));
  assert.ok(userModule.findings?.some(finding => finding.code === "timestamp-without-bound-import"));
  assert.ok(userModule.findings?.some(finding => finding.code === "eager-and-delay"));
  assert.ok(userModule.findings?.some(finding => finding.code === "protected-delay-iat-own-section"));
  assert.ok(
    userModule.findings?.some(
      finding =>
        finding.code === "protected-delay-iat-own-section" &&
        finding.message.includes("canonical .didat section")
    )
  );
  assert.ok(!userModule.findings?.some(finding => finding.code === "delay-iat-outside-directory"));
  assert.deepEqual(userModule.delayImports[0], {
    delayImportIndex: 0,
    iatDirectoryRelation: "outside-directory"
  });

  const orphanModule = expectDefined(result.modules.find(module => module.moduleKey === "orphan.dll"));
  assert.equal(orphanModule.boundImports.length, 1);
  assert.ok(orphanModule.findings?.some(finding => finding.code === "bound-without-import"));
  assert.ok(
    orphanModule.findings?.some(
      finding =>
        finding.code === "bound-without-import" &&
        finding.message === "Bound import entry without a matching eager import descriptor."
    )
  );
});

void test("analyzeImportLinking confirms protected delay-load IATs in separate sections without the own-section flag", () => {
  const { imports, boundImports, delayImports, iat, loadcfg } =
    createImportLinkingProtectedSeparateSectionInputs();

  const result = expectDefined(
    analyzeImportLinking(
      imports,
      boundImports,
      delayImports,
      iat,
      loadcfg,
      createImportLinkingSections()
    )
  );

  const userModule = expectDefined(result.modules.find(module => module.moduleKey === "user32.dll"));
  assert.ok(
    userModule.findings?.some(finding => finding.code === "protected-delay-iat-separate-section")
  );
  assert.ok(
    userModule.findings?.some(
      finding =>
        finding.code === "protected-delay-iat-separate-section" &&
        finding.message.includes("protected delay-load IAT handling")
    )
  );
});

void test("analyzeImportLinking reports delay-load IATs outside the main IAT without protection context", () => {
  const { imports, boundImports, delayImports, iat, loadcfg } =
    createImportLinkingOutsideDirectoryInputs();

  const result = expectDefined(
    analyzeImportLinking(
      imports,
      boundImports,
      delayImports,
      iat,
      loadcfg,
      createImportLinkingSections()
    )
  );

  const userModule = expectDefined(result.modules.find(module => module.moduleKey === "user32.dll"));
  assert.ok(userModule.findings?.some(finding => finding.code === "delay-iat-outside-directory"));
  assert.ok(
    userModule.findings?.some(
      finding =>
        finding.code === "delay-iat-outside-directory" &&
        finding.message.includes("resolves to section .didat")
    )
  );
  assert.ok(
    !userModule.findings?.some(finding => finding.code === "protected-delay-iat-own-section")
  );
});

void test("analyzeImportLinking warns when GuardFlags advertise an own-section delay IAT that is not confirmed", () => {
  const { imports, boundImports, delayImports, iat, loadcfg } =
    createImportLinkingOwnSectionMismatchInputs();

  const result = expectDefined(
    analyzeImportLinking(
      imports,
      boundImports,
      delayImports,
      iat,
      loadcfg,
      createImportLinkingMainSectionOnly()
    )
  );

  const userModule = expectDefined(result.modules.find(module => module.moduleKey === "user32.dll"));
  assert.ok(userModule.findings?.some(finding => finding.code === "delay-iat-covered"));
  assert.ok(
    userModule.findings?.some(
      finding =>
        finding.code === "delay-iat-own-section-mismatch" &&
        finding.message.includes("does not resolve to a distinct section")
    )
  );
  assert.ok(
    !userModule.findings?.some(finding => finding.code === "protected-delay-iat-own-section")
  );
});

void test("analyzeImportLinking returns null when no import-related structures are present", () => {
  assert.equal(
    analyzeImportLinking({ entries: [], thunkEntrySize: Uint32Array.BYTES_PER_ELEMENT }, null, null, null, null, []),
    null
  );
});

void test("analyzeImportLinking normalizes module keys case-insensitively and trims whitespace", () => {
  const { imports, boundImports, delayImports, iat, loadcfg } = createImportLinkingInputs();
  expectDefined(imports.entries[0]).dll = "  KERNEL32.DLL  ";
  expectDefined(boundImports.entries[0]).name = "kernel32.dll";
  expectDefined(delayImports.entries[0]).name = "  USER32.dll  ";

  const result = expectDefined(
    analyzeImportLinking(
      imports,
      boundImports,
      delayImports,
      iat,
      loadcfg,
      createImportLinkingSections()
    )
  );

  assert.equal(result.modules.filter(module => module.moduleKey === "kernel32.dll").length, 1);
  assert.equal(result.modules.filter(module => module.moduleKey === "user32.dll").length, 1);
});

void test("analyzeImportLinking records missing-directory and missing-table-rva relations explicitly", () => {
  const { imports, boundImports, delayImports, loadcfg } = createImportLinkingInputs();
  const firstImport = expectDefined(imports.entries[0]);
  firstImport.firstThunkRva = 0;
  firstImport.lookupSource = "missing";

  const result = expectDefined(
    analyzeImportLinking(imports, boundImports, delayImports, null, loadcfg, [])
  );

  const kernelModule = expectDefined(result.modules.find(module => module.moduleKey === "kernel32.dll"));
  const userModule = expectDefined(result.modules.find(module => module.moduleKey === "user32.dll"));
  assert.equal(kernelModule.imports[0]?.iatDirectoryRelation, "missing-table-rva");
  assert.equal(userModule.imports[0]?.iatDirectoryRelation, "missing-directory");
  assert.equal(userModule.delayImports[0]?.iatDirectoryRelation, "missing-directory");
  assert.equal(result.inferredEagerIat?.relationToDeclared, "declared-absent");
});
