import assert from "node:assert/strict";
import test from "node:test";
import { compareNativeAotMapReference } from "./native-aot-map-reference-compare.js";

// Reference.csproj native-maps input.json output.json uses upstream .NET NativeHashtable/NativeReader.
void test("NativeAOT PE and ELF method maps match the independent .NET reader", async context => {
  const reference = process.env["BINARY101_NATIVE_AOT_MAP_REFERENCE"];
  if (!reference) { context.skip("Set BINARY101_NATIVE_AOT_MAP_REFERENCE to reference JSON."); return; }

  const counts = await compareNativeAotMapReference(reference);

  assert.ok(counts.files > 0);
  assert.ok(counts.invokes > 0);
  assert.ok(counts.stackTraceMethods > 0);
  assert.ok(counts.seeds > 0);
  context.diagnostic(JSON.stringify(counts));
});
