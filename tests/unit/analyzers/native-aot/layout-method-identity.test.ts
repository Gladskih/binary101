import assert from "node:assert/strict";
import test from "node:test";
import { readLayoutMethodIdentity, relativeLayoutCursor } from "../../../../analyzers/native-aot/layout-method-identity.js";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatCursor } from "../../../../analyzers/native-aot/native-format-cursor.js";

// Legacy name and relative-signature fields follow the .NET 9 NativeLayout writer.
// https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/nativeaot/System.Private.TypeLoader/src/Internal/Runtime/TypeLoader/TypeLoaderEnvironment.SignatureParsing.cs

void test("method identities select metadata tokens or legacy names with relative signatures", () => {
  // Legacy layout: string length 1, UTF-8 "M", signed relative signature delta +1.
  const legacy = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(2, 77, 2, 0), "dotnet9"), 0);
  // Modern layout identity is a NativeFormat metadata token: encoded 84 decodes to token 42.
  const modern = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(84)), 0);

  assert.deepEqual(readLayoutMethodIdentity(legacy), { methodName: "M", methodSignatureOffset: 3 });
  assert.equal(legacy.offset, 3);
  assert.deepEqual(readLayoutMethodIdentity(modern), { methodToken: 42 });
  assert.equal(modern.offset, 1);
});

void test("relative NativeLayout signatures validate signed targets and truncated offsets", () => {
  // Signed deltas -1, +1 and an incomplete continuation all target outside their one-byte prefix.
  assert.throws(() => relativeLayoutCursor(new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(254)), 0)),
    /outside/);
  assert.throws(() => relativeLayoutCursor(new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(2)), 0)),
    /outside/);
  assert.throws(() => relativeLayoutCursor(new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(1)), 0)),
    /outside/);
});
