import assert from "node:assert/strict";
import { test } from "node:test";
import { compareNativeFormatReference } from "./native-format-reference-compare.js";

// Generate the JSON with aot-r2r-reference/Reference.csproj using unmodified
// https://github.com/dotnet/runtime/tree/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat
void test("NativeFormat structures match the generated upstream .NET reader", async context => {
  const blob = process.env["BINARY101_NATIVE_FORMAT_BLOB"];
  const reference = process.env["BINARY101_NATIVE_FORMAT_REFERENCE"];
  if (!blob || !reference) { context.skip("Set NativeFormat blob and reference JSON paths."); return; }

  const compared = await compareNativeFormatReference(blob, reference);

  assert.ok(compared.records > 0);
  assert.ok(compared.fields > compared.records);
  context.diagnostic(`Compared ${compared.records} records and ${compared.fields} fields.`);
});
