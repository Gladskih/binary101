import { createNativeAotRuntimeTypeFixture } from "./native-aot-runtime-type-fixture.js";
import { createNativeHashtableFixture } from "./native-hashtable-fixture.js";

export const createNativeAotRuntimeTailFixture = (pointerSize: 4 | 8 = 8) => {
  const fixture = createNativeAotRuntimeTypeFixture(pointerSize);
  // Dispatch + finalizer + sealed vtable flags; MethodTable.GetFieldOffset (.NET 9/10).
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/MethodTable.cs
  const flags = 0x04540000;
  fixture.view.setUint32(0x180, flags, true);
  const tailRva = 0x180 + 16 + pointerSize + pointerSize * 4;
  const dispatchRva = 0x260;
  const sealedRva = 0x2a0;
  fixture.view.setInt32(tailRva + 8, dispatchRva - tailRva - 8, true);
  fixture.view.setInt32(tailRva + 12, fixture.codeRvas[1]! - tailRva - 12, true);
  fixture.view.setInt32(tailRva + 16, sealedRva - tailRva - 16, true);
  // Four count ushorts, standard/default entries (6 bytes), static entries (8 bytes).
  // SpecialDispatchMapSlot: 0xfffe=Diamond, 0xffff=Reabstraction (never sealed indices).
  fixture.view.setUint16(dispatchRva, 2, true);
  fixture.view.setUint16(dispatchRva + 2, 1, true);
  fixture.view.setUint16(dispatchRva + 4, 1, true);
  fixture.view.setUint16(dispatchRva + 6, 1, true);
  fixture.view.setUint16(dispatchRva + 12, 0, true);
  fixture.view.setUint16(dispatchRva + 18, 3, true);
  fixture.view.setUint16(dispatchRva + 24, 0xfffe, true);
  fixture.view.setUint16(dispatchRva + 30, 3, true);
  fixture.view.setUint16(dispatchRva + 32, 1, true);
  fixture.view.setUint16(dispatchRva + 38, 0xffff, true);
  fixture.view.setUint16(dispatchRva + 40, 2, true);
  fixture.view.setInt32(sealedRva, fixture.codeRvas[0]! - sealedRva, true);
  return { ...fixture, flags, tailRva, dispatchRva, sealedRva, type: {
    rva: 0x180, flags, baseSize: 24, numVtableSlots: 3, numInterfaces: 1,
    hashCode: 0x12345678, slots: []
  } };
};

export const createNativeAotRuntimeTailMapFixture = () => {
  const fixture = createNativeAotRuntimeTailFixture();
  const bytes = createNativeHashtableFixture([Uint8Array.of(0, 20)]);
  fixture.bytes.set(bytes, fixture.mapRva);
  fixture.sections[0] = { type: 301, rva: fixture.mapRva, size: bytes.length };
  return fixture;
};
