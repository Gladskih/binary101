import assert from "node:assert/strict";
import test from "node:test";
import { nativeTypeLookbackOffset } from "../../../../analyzers/native-aot/type-lookback.js";

// NativePrimitiveDecoder.GetUnsignedEncodingSize(data << 4) boundaries; the type tag
// does not affect the canonical width. NativeParser.GetLookbackParser adds another 2.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.Metadata.cs
for (const [data, width] of [[0, 1], [7, 1], [8, 2], [1023, 2], [1024, 3],
  [131071, 3], [131072, 4], [16777215, 4], [16777216, 5], [268435455, 5]]) {
  void test(`NativeLayout lookback ${data} uses a canonical width of ${width}`, () => {
    assert.equal(nativeTypeLookbackOffset(0, data!), -data! - width! - 2);
    assert.equal(nativeTypeLookbackOffset(data! + width! + 2, data!), 0);
  });
}
