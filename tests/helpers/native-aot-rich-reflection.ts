import type { NativeAotReflectionScope } from "../../analyzers/native-aot/format.js";

export const createRichNativeAotScope = (): NativeAotReflectionScope => ({
  name: "Demo<Assembly>", moduleName: "Demo.dll",
  version: { major: 1, minor: 2, build: 3, revision: 4 },
  types: [{ namespace: "Demo", name: "Container",
    methods: [{ name: "Convert", flags: 6, implementationFlags: 1,
      signature: { callingConvention: 32, genericParameterCount: 1, returnType: "!!0",
        parameters: ["!0&"], varArgParameters: ["System.String"] },
      parameters: [{ sequence: 1, name: "input", flags: 16 }],
      genericParameters: [{ number: 0, flags: 8, kind: 1, name: "T", constraints: ["Demo.IMarker"] }]
    }, { name: "Unknown" }],
    fields: [{ name: "Value", type: "System.Int32", flags: 6, offset: 12 }, { name: "Unknown" }],
    definition: { flags: 1, size: 32, packingSize: 8, baseType: "System.Object",
      interfaces: ["Demo.IMarker"], genericParameters: [
        { number: 0, flags: 4, kind: 0, name: "T", constraints: [] }],
      properties: [{ name: "Item", type: "System.String", flags: 0,
        parameters: ["System.Int32"], semantics: [{ method: "get_Item", attributes: 2 }] },
      { name: "Unknown" }],
      events: [{ name: "Changed", type: "System.EventHandler", flags: 0,
        semantics: [{ method: "add_Changed", attributes: 8 }] }, { name: "Unknown" }]
    }
  }, { namespace: "", name: "Marker", methods: [], fields: [] }]
});
