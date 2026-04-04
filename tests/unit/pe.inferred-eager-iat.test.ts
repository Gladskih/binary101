"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeInferredEagerIat } from "../../analyzers/pe/inferred-eager-iat.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { createImportLinkingInputs } from "../fixtures/pe-import-linking-fixture.js";

void test("analyzeInferredEagerIat infers eager IAT ranges even when IMAGE_DIRECTORY_ENTRY_IAT is absent", () => {
  const { imports } = createImportLinkingInputs();

  const result = analyzeInferredEagerIat(imports, null);
  const inferredEagerIat = expectDefined(result.inferredEagerIat);
  const firstImport = expectDefined(imports.entries[0]);
  const secondImport = expectDefined(imports.entries[1]);
  const lowerBoundThunkRangeSize = imports.thunkEntrySize * 2;

  assert.equal(inferredEagerIat.relationToDeclared, "declared-absent");
  assert.deepEqual(inferredEagerIat.ranges, [
    {
      startRva: firstImport.firstThunkRva,
      endRva: firstImport.firstThunkRva + lowerBoundThunkRangeSize,
      size: lowerBoundThunkRangeSize,
      importIndices: [0],
      descriptorCount: 1
    },
    {
      startRva: secondImport.firstThunkRva,
      endRva: secondImport.firstThunkRva + lowerBoundThunkRangeSize,
      size: lowerBoundThunkRangeSize,
      importIndices: [1],
      descriptorCount: 1
    }
  ]);
  assert.ok(
    result.findings.some(
      finding => finding.code === "declared-iat-absent-inferred-eager"
    )
  );
});

void test("analyzeInferredEagerIat confirms an exact declared IAT match when one eager descriptor fills the whole range", () => {
  const { imports, iat } = createImportLinkingInputs();
  const firstImport = expectDefined(imports.entries[0]);
  imports.entries = [firstImport];
  const exactMatchSize = imports.thunkEntrySize * (firstImport.functions.length + 1);
  iat.rva = firstImport.firstThunkRva;
  iat.size = exactMatchSize;

  const result = analyzeInferredEagerIat(imports, iat);

  assert.equal(result.inferredEagerIat?.relationToDeclared, "exact-match");
  assert.ok(result.findings.some(finding => finding.code === "declared-iat-exact-match"));
});

void test("analyzeInferredEagerIat warns when the declared IAT misses inferred eager IAT slots", () => {
  const { imports, iat } = createImportLinkingInputs();
  const firstImport = expectDefined(imports.entries[0]);
  iat.rva = firstImport.firstThunkRva + imports.thunkEntrySize;
  iat.size = imports.thunkEntrySize;

  const result = analyzeInferredEagerIat(imports, iat);

  assert.equal(result.inferredEagerIat?.relationToDeclared, "declared-misses-inferred");
  assert.ok(
    result.findings.some(finding => finding.code === "declared-iat-misses-inferred-eager")
  );
});
