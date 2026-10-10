import { createNativeAotRuntimeTypeFixture, runtimeTypeFixtureFlags } from "./native-aot-runtime-type-fixture.js";
import { createNativeHashtableFixture } from "./native-hashtable-fixture.js";

// GetFieldOffset lays out static relative pointers in this order; dispatch records
// use ushort fields. These definitions describe the fixture independently of the parser.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/MethodTable.cs
export const runtimeTailFixtureLayout = {
  dispatchPointer: 2 * Int32Array.BYTES_PER_ELEMENT,
  finalizerPointer: 3 * Int32Array.BYTES_PER_ELEMENT,
  sealedPointer: 4 * Int32Array.BYTES_PER_ELEMENT,
  countsSize: 4 * Uint16Array.BYTES_PER_ELEMENT,
  standardEntrySize: 3 * Uint16Array.BYTES_PER_ELEMENT,
  staticEntrySize: 4 * Uint16Array.BYTES_PER_ELEMENT,
  implementationSlot: 2 * Uint16Array.BYTES_PER_ELEMENT,
  contextSource: 3 * Uint16Array.BYTES_PER_ELEMENT
} as const;

export const createNativeAotRuntimeTailFixture = (pointerSize: 4 | 8 = 8) => {
  const fixture = createNativeAotRuntimeTypeFixture(pointerSize);
  // Dispatch + finalizer + sealed vtable flags; MethodTable.GetFieldOffset (.NET 9/10).
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/MethodTable.cs
  const flags = runtimeTypeFixtureFlags.class | runtimeTypeFixtureFlags.dispatch |
    runtimeTypeFixtureFlags.finalizer | runtimeTypeFixtureFlags.sealedVtable;
  fixture.view.setUint32(fixture.typeRva, flags, true);
  // Three vtable slots and one interface pointer precede the optional relative fields.
  const tailRva = fixture.vtableRva + pointerSize * (3 + 1);
  // Incidental, nonoverlapping storage after common fixups; not format-required addresses.
  const dispatchRva = fixture.dictionaryRva + Uint32Array.BYTES_PER_ELEMENT * 16;
  const sealedRva = dispatchRva + Uint32Array.BYTES_PER_ELEMENT * 16;
  fixture.view.setInt32(tailRva + runtimeTailFixtureLayout.dispatchPointer,
    dispatchRva - tailRva - runtimeTailFixtureLayout.dispatchPointer, true);
  fixture.view.setInt32(tailRva + runtimeTailFixtureLayout.finalizerPointer,
    fixture.codeRvas[1]! - tailRva - runtimeTailFixtureLayout.finalizerPointer, true);
  fixture.view.setInt32(tailRva + runtimeTailFixtureLayout.sealedPointer,
    sealedRva - tailRva - runtimeTailFixtureLayout.sealedPointer, true);
  // Four count ushorts, standard/default entries (three ushorts), static entries
  // (four ushorts). Tail fields: TypeManagerIndirection, WritableData, DispatchMap,
  // Finalizer, SealedVirtualSlots; each static relative pointer occupies four bytes.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/MethodTable.cs
  // SpecialDispatchMapSlot: 0xfffe=Diamond, 0xffff=Reabstraction (never sealed indices).
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/RuntimeConstants.cs
  const fields = [2, 1, 1, 1, // Counts: standard, default, static, default static.
    0, 0, 0, // Standard implementation in ordinary vtable slot zero.
    0, 0, 3, // Standard implementation in first sealed slot (after three vtable slots).
    0, 0, 0xfffe, // Default diamond marker, not code.
    0, 0, 3, 1, // Static implementation; context source is owning type.
    0, 0, 0xffff, 2]; // Reabstraction marker; context is first interface.
  fields.forEach((value, index) => fixture.view.setUint16(
    dispatchRva + index * Uint16Array.BYTES_PER_ELEMENT, value, true));
  fixture.view.setInt32(sealedRva, fixture.codeRvas[0]! - sealedRva, true);
  return { ...fixture, flags, tailRva, dispatchRva, sealedRva, type: {
    rva: fixture.typeRva, flags, baseSize: 3 * 8, numVtableSlots: 3, numInterfaces: 1,
    hashCode: 0x12345678, slots: []
  } };
};

export const createNativeAotRuntimeTailMapFixture = () => {
  const fixture = createNativeAotRuntimeTailFixture();
  const bytes = createNativeHashtableFixture([Uint8Array.of(0, 10 * 2)]);
  fixture.bytes.set(bytes, fixture.mapRva);
  fixture.sections[0] = { type: 301, rva: fixture.mapRva, size: bytes.length };
  return fixture;
};
