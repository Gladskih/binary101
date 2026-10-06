import { createFunctionEntryFixture } from "./native-aot-function-map-fixture.js";
import { NativeAotFunctionReferences } from "../../analyzers/native-aot/function-references.js";
import { createNativeHashtableFixture } from "./native-hashtable-fixture.js";

export const createNativeAotRuntimeTypeFixture = (pointerSize: 4 | 8 = 8) => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 20));
  fixture.image.pointerSize = pointerSize;
  fixture.view.setInt32(fixture.fixupsRva, 0x180 - fixture.fixupsRva, true);
  // MethodTable fixed fields and the following pointer-sized virtual slots (v8-v10).
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/MethodTable.cs
  fixture.view.setUint32(0x180, 0x04000000, true);
  fixture.view.setUint32(0x184, 24, true);
  fixture.view.setUint16(0x188 + pointerSize, 3, true);
  fixture.view.setUint16(0x18a + pointerSize, 1, true);
  fixture.view.setUint32(0x18c + pointerSize, 0x12345678, true);
  fixture.image.readPointerValue = async address => {
    const value = fixture.view.getUint32(address, true);
    return BigInt(value);
  };
  fixture.image.readPointerTarget = async address => fixture.view.getUint32(address, true);
  fixture.view.setUint32(0x190 + pointerSize, fixture.codeRvas[0]!, true);
  fixture.view.setUint32(0x190 + pointerSize * 2, 0x220, true);
  return { ...fixture, references: new NativeAotFunctionReferences(
    fixture.image, fixture.sections, fixture.issues) };
};

export const createNativeAotTypeMapFixture = () => {
  const fixture = createNativeAotRuntimeTypeFixture();
  const map = createNativeHashtableFixture([Uint8Array.of(0, 20)]);
  fixture.bytes.set(map, fixture.mapRva);
  fixture.sections[0] = { type: 301, rva: fixture.mapRva, size: map.length };
  return fixture;
};
