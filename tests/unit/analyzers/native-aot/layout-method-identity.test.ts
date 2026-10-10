import assert from "node:assert/strict";
import test from "node:test";
import { readLayoutMethodIdentity, relativeLayoutCursor } from "../../../../analyzers/native-aot/layout-method-identity.js";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatCursor } from "../../../../analyzers/native-aot/native-format-cursor.js";

void test("method identities select metadata tokens or legacy names with relative signatures", () => {
  const legacy = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(2, 77, 2, 0), "dotnet9"), 0);
  const modern = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(84)), 0);

  assert.deepEqual(readLayoutMethodIdentity(legacy), { methodName: "M", methodSignatureOffset: 3 });
  assert.equal(legacy.offset, 3);
  assert.deepEqual(readLayoutMethodIdentity(modern), { methodToken: 42 });
  assert.equal(modern.offset, 1);
});

void test("relative NativeLayout signatures validate signed targets and truncated offsets", () => {
  assert.throws(() => relativeLayoutCursor(new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(254)), 0)),
    /outside/);
  assert.throws(() => relativeLayoutCursor(new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(2)), 0)),
    /outside/);
  assert.throws(() => relativeLayoutCursor(new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(1)), 0)),
    /outside/);
});
