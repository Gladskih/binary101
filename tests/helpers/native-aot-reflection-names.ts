import type { NativeAotReflectionMetadata } from "../../analyzers/native-aot/format.js";

export const syntheticNativeAotScope = {
  name: "HelloCSharp", moduleName: "HelloCSharp.dll",
  version: { major: 1, minor: 2, build: 3, revision: 4 },
  types: [
    { namespace: "Demo", name: "Program", methods: ["Main"],
      fields: ["Count", "<Name>k__BackingField"] },
    { namespace: "Demo", name: "Program+Nested", methods: ["Work"], fields: ["Value"] },
    { namespace: "Demo.Inner", name: "Worker", methods: ["Run"], fields: [] }
  ]
};

// Name traversal assertions remain independent of the additional member details.
export const nativeAotReflectionNames = (metadata: NativeAotReflectionMetadata) => ({
  ...metadata,
  scopes: metadata.scopes.map(scope => ({
    ...scope,
    types: scope.types.map(type => ({
      namespace: type.namespace, name: type.name,
      methods: type.methods.map(method => method.name),
      fields: type.fields.map(field => field.name)
    }))
  }))
});
