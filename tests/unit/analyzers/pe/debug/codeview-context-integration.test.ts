import assert from "node:assert/strict";
import { test } from "node:test";
import { legacyReader } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewContextModule } from "../../../../fixtures/pe-codeview-contexts.js";
import { readLegacyCodeViewModuleSymbols } from "../../../../../analyzers/pe/debug/legacy-codeview-symbols.js";
import { analyzeCodeViewLocalScopes } from "../../../../../analyzers/pe/debug/codeview-local-scopes.js";
import { buildCodeViewLocalTables } from "../../../../../renderers/pe/codeview-local-tables.js";

void test("Inline, WITH and thunk locals retain their distinct validated lexical contexts", async () => {
  const warnings: string[] = [];
  const data = await readLegacyCodeViewModuleSymbols(legacyReader(codeViewContextModule(), warnings));
  const result = analyzeCodeViewLocalScopes(data);
  const locals = result.bindings.filter(binding => binding.record.local);

  assert.deepEqual(warnings, []);
  assert.deepEqual(result.issues, []);
  assert.deepEqual(locals.map(binding => binding.context?.scope?.kind), ["inline", "with", "thunk"]);
  assert.deepEqual(locals.map(binding => binding.procedure?.name), ["outer", "outer", undefined]);
  assert.deepEqual(locals.map(binding => binding.issues), [[], [], []]);
});

void test("Context tables retain named thunks, WITH expressions and inline statistics", async () => {
  const data = await readLegacyCodeViewModuleSymbols(legacyReader(codeViewContextModule(), []));
  const tables = buildCodeViewLocalTables({ signature: "NB09", directories: [{ flags: 0,
    subsections: [{ type: 0x125, module: 1, size: 512, offset: 0, data }] }] }, 0x8664);
  const scopes = tables.find(table => table.key === "lexicalScopes")!;

  assert.equal(scopes.rows.length, 3);
  assert.ok(scopes.rows.some(row => row.includes("thunk: adjustor")));
  assert.ok(scopes.rows.some(row => row.includes("with: object.member")));
  assert.ok(scopes.rows.some(row => row.some(value => value.includes("12 declared code bytes"))));
});
