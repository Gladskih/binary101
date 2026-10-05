import assert from "node:assert/strict";
import { test } from "node:test";
import { compareReadyToRunReference } from "./ready-to-run-reference-compare.js";

// Reference.csproj r2r output.jsonl paths... executes .NET's NativeArray/NativeReader
// and System.Reflection.PortableExecutable against a local assembly corpus.
void test("ReadyToRun entry points and imports match the independent .NET reference", async context => {
  const reference = process.env["BINARY101_R2R_REFERENCE"];
  if (!reference) { context.skip("Set BINARY101_R2R_REFERENCE to generated reference JSONL."); return; }

  const counts = await compareReadyToRunReference(reference);

  assert.ok(counts.files > 0);
  assert.ok(counts.methods > 0);
  assert.ok(counts.cells > 0);
  context.diagnostic(JSON.stringify(counts));
});
