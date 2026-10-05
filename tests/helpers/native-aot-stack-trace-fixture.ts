import { createNativeAotInvokeFixture } from "./native-aot-invoke-fixture.js";

export const createNativeAotStackTraceFixture = () => {
  const fixture = createNativeAotInvokeFixture();
  const rva = fixture.mapRva;
  const bytes = new Uint8Array(22);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 2, true);
  // StackTraceDataCommand: owning type=1, name=2, generic signature=8, hidden=16.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/StackTraceData.cs
  bytes[4] = 0x1b;
  view.setUint32(5, 0x01000020, true);
  bytes.set([20, 40, 60], 9); // NativeFormat metadata offsets 10, 20, 30.
  view.setInt32(12, fixture.codeRvas[0]! - rva - 12, true);
  bytes[16] = 4; // Ordinary signature update; all other context fields carry over.
  bytes[17] = 80;
  view.setInt32(18, fixture.codeRvas[1]! - rva - 18, true);
  fixture.bytes.set(bytes, rva);
  return { ...fixture, section: { type: 327, rva, size: bytes.length }, length: bytes.length };
};
