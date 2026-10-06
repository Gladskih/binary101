import type { NativeAotFunctionMaps } from "../../analyzers/native-aot/function-map-types.js";

export const createFunctionMapModels = (): NativeAotFunctionMaps => ({ warnings: ["<global>"], maps: [
  { type: 310, warnings: [], entries: [{ typeIndex: 0, staticBaseIndex: 1, entrypointRva: 0x40 }] },
  { type: 316, warnings: ["<struct>"], entries: [{ typeIndex: 0, header: 5, nativeSize: 32,
    marshalRva: 0x40, unmarshalRva: 0x300, cleanupRva: null, fields: [{ name: "<field>", offset: 4 }] }] },
  { type: 317, warnings: [], entries: [{ typeIndex: 1, openStaticRva: 0x40, closedRva: null,
    forwardCreationRva: 0x300 }] },
  { type: 321, warnings: [], entries: [{ typeIndex: 1, layoutOffset: 0, layout: {
    classConstructorRva: 0x40, dictionaryMethods: [{ flags: 4, signatureOffset: 8,
      methodToken: 10, entrypointRva: 0x300 }] } }] },
  { type: 322, warnings: [], entries: [{ signatureOffset: 0, layoutOffset: 8, flags: 5,
    declaringTypeIndex: 1, methodToken: 10, genericArgumentIndices: [0], entrypointRva: 0x40,
    layout: { classConstructorRva: null, dictionaryMethods: [] } }] },
  { type: 336, warnings: [], entries: [{ declaringTypeIndex: 1, methodToken: 10,
    genericArgumentIndices: [], entrypointRva: 0x300 }] }
] });
