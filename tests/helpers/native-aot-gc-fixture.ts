import { createNativeAotRuntimeTypeFixture } from "./native-aot-runtime-type-fixture.js";

export const createNativeAotObjectGcFixture = (width: 4 | 8 = 8) => {
  const fixture = createNativeAotRuntimeTypeFixture(width);
  const word = (address: number, value: bigint): void => {
    if (width === 8) fixture.view.setBigUint64(address, BigInt.asUintN(64, value), true);
    else fixture.view.setUint32(address, Number(BigInt.asUintN(32, value)), true);
  };
  // GCDescEncoder stores a positive series count, then alternating series start and
  // signed size-minus-base-size words backwards from MethodTable. The two segments
  // below resolve to [width, width] and [3*width, 2*width].
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/GCDescEncoder.cs
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/gc/gcdesc.h
  const type = { rva: 0x180, flags: 0x01000000, baseSize: width * 6, numVtableSlots: 3 };
  word(type.rva - width, 2n);
  word(type.rva - width * 2, BigInt(width));
  word(type.rva - width * 3, BigInt(-width * 5));
  word(type.rva - width * 4, BigInt(width * 3));
  word(type.rva - width * 5, BigInt(-width * 4));
  return { ...fixture, type, word };
};

export const createNativeAotReferenceArrayGcFixture = (width: 4 | 8 = 8) => {
  const fixture = createNativeAotObjectGcFixture(width);
  // TYP_ARRAY (0x18), HasPointers, and component size encode an SZ reference array;
  // positive count 1, data offset 2*width, and -baseSize are the GCDesc array form.
  // The bit meanings and backwards descriptor layout are defined by the sources above.
  const type = { ...fixture.type, flags: (0xe1000000 | width) >>> 0, baseSize: width * 3 };
  fixture.word(type.rva - width, 1n);
  fixture.word(type.rva - width * 2, BigInt(width * 2));
  fixture.word(type.rva - width * 3, BigInt(-type.baseSize));
  return { ...fixture, type };
};

export const createNativeAotRepeatingArrayGcFixture = (width: 4 | 8 = 8) => {
  const fixture = createNativeAotReferenceArrayGcFixture(width);
  // Negative count -2 selects two repeating pointer/skip entries. Each packed word
  // uses equal pointer-sized halves; count 1/skip width then count 2/skip width
  // produce a 4*width component stride with two references in its second run.
  const type = { ...fixture.type, flags: (0xe1000000 | width * 5) >>> 0 };
  const packed = BigInt(width) << BigInt(width * 4);
  fixture.word(type.rva - width, -2n);
  fixture.word(type.rva - width * 2, BigInt(width * 3));
  fixture.word(type.rva - width * 3, packed | 1n);
  fixture.word(type.rva - width * 4, packed | 2n);
  return { ...fixture, type };
};
