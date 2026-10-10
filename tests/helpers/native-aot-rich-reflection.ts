import type { NativeAotReflectionScope } from "../../analyzers/native-aot/format.js";

// The member, method-implementation, generic-parameter, and accessor flags mirror CLI metadata.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/cor.h
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
export const createRichNativeAotScope = (): NativeAotReflectionScope => ({
  name: "Demo<Assembly>", moduleName: "Demo.dll",
  version: { major: 1, minor: 2, build: 3, revision: 4 },
  types: [{ namespace: "Demo", name: "Container",
    methods: [{ name: "Convert", flags: 6, implementationFlags: 1,
      // 6=mdPublic, 1=miNative, 0x20=HasThis; generic parameter flags 8=NotNullableValueType.
      signature: { callingConvention: 0x20, genericParameterCount: 1, returnType: "!!0",
        parameters: ["!0&"], varArgParameters: ["System.String"] },
      parameters: [{ sequence: 1, name: "input", flags: 16 }], // pdOptional.
      genericParameters: [{ number: 0, flags: 8, kind: 1, name: "T", constraints: ["Demo.IMarker"] }]
    }, { name: "Unknown" }],
    // 6=mdPublic; offset 12 is a synthetic field location for the renderer's offset column.
    fields: [{ name: "Value", type: "System.Int32", flags: 6, offset: 12 }, { name: "Unknown" }],
    // Public type flag and an intentionally synthetic 32-byte, 8-byte-packed type layout.
    definition: { flags: 1, size: 32, packingSize: 8, baseType: "System.Object",
      interfaces: ["Demo.IMarker"], genericParameters: [
        // 4=ReferenceTypeConstraint, kind 0=type parameter.
        { number: 0, flags: 4, kind: 0, name: "T", constraints: [] }],
      properties: [{ name: "Item", type: "System.String", flags: 0,
        // MethodSemantics.Getter is 2; AddOn is 8 for the event below.
        parameters: ["System.Int32"], semantics: [{ method: "get_Item", attributes: 2 }] },
      { name: "Unknown" }],
      events: [{ name: "Changed", type: "System.EventHandler", flags: 0,
        semantics: [{ method: "add_Changed", attributes: 8 }] }, { name: "Unknown" }]
    }
  }, { namespace: "", name: "Marker", methods: [], fields: [] }]
});
