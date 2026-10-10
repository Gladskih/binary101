import { createFunctionEntryFixture } from "./native-aot-function-map-fixture.js";
import { NativeAotFunctionReferences } from "../../analyzers/native-aot/function-references.js";
import { createNativeHashtableFixture } from "./native-hashtable-fixture.js";

// EETypeFlags and EETypeElementType, deliberately independent of production code.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/MethodTable.Constants.cs
export const runtimeTypeFixtureFlags = {
  class: 0x14 << 26, interface: 0x15 << 26,
  dispatch: 0x00040000, dynamic: 0x00080000,
  finalizer: 0x00100000, sealedVtable: 0x00400000
} as const;

// NativeAOT ModuleHeaders.cs uses 10.1 for .NET 9 and 16.0 for .NET 10.
// https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
export const nativeAotFixtureVersions = {
  dotnet9: { majorVersion: 10, minorVersion: 1 },
  dotnet10: { majorVersion: 16, minorVersion: 0 }
} as const;

export const createNativeAotRuntimeTypeFixture = (pointerSize: 4 | 8 = 8) => {
  // TypeMap tuple: common-fixup index 0 and metadata handle 10, short unsigned encoding.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/TypeMetadataMapNode.cs
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 10 * 2));
  fixture.image.pointerSize = pointerSize;
  // Incidental addresses: place the type midway between the map and common fixups.
  const typeRva = fixture.mapRva + (fixture.fixupsRva - fixture.mapRva) / 2;
  const dictionaryRva = fixture.fixupsRva + Uint32Array.BYTES_PER_ELEMENT * 8;
  fixture.view.setInt32(fixture.fixupsRva, typeRva - fixture.fixupsRva, true);
  // MethodTable fixed fields and the following pointer-sized virtual slots (v8-v10).
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/MethodTable.cs
  fixture.view.setUint32(typeRva, runtimeTypeFixtureFlags.class, true);
  fixture.view.setUint32(typeRva + 4, 3 * 8, true); // Incidental 24-byte object base size.
  const countsRva = typeRva + 2 * Uint32Array.BYTES_PER_ELEMENT + pointerSize;
  fixture.view.setUint16(countsRva, 3, true); // Method, dictionary and null slots.
  fixture.view.setUint16(countsRva + Uint16Array.BYTES_PER_ELEMENT, 1, true); // One interface.
  // Distinct sentinel bytes exercise the little-endian UInt32 hash field.
  fixture.view.setUint32(countsRva + 2 * Uint16Array.BYTES_PER_ELEMENT, 0x12345678, true);
  fixture.image.readPointerValue = async address => {
    const value = fixture.view.getUint32(address, true);
    return BigInt(value);
  };
  fixture.image.readPointerTarget = async address => fixture.view.getUint32(address, true);
  const vtableRva = countsRva + 2 * Uint16Array.BYTES_PER_ELEMENT + Uint32Array.BYTES_PER_ELEMENT;
  fixture.view.setUint32(vtableRva, fixture.codeRvas[0]!, true);
  fixture.view.setUint32(vtableRva + pointerSize, dictionaryRva, true);
  return { ...fixture, typeRva, dictionaryRva, vtableRva, countsRva,
    references: new NativeAotFunctionReferences(
    fixture.image, fixture.sections, fixture.issues) };
};

export const createNativeAotTypeMapFixture = () => {
  const fixture = createNativeAotRuntimeTypeFixture();
  const map = createNativeHashtableFixture([Uint8Array.of(0, 10 * 2)]);
  fixture.bytes.set(map, fixture.mapRva);
  // ReflectionMapBlob.TypeMap=1; NativeAOT shifts reflection section IDs by 300.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/MetadataBlob.cs
  fixture.sections[0] = { type: 300 + 1, rva: fixture.mapRva, size: map.length };
  return fixture;
};
