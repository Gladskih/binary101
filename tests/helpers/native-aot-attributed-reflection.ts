import type { NativeAotAttribute } from "../../analyzers/native-aot/native-format-attributes.js";
import { createRichNativeAotScope } from "./native-aot-rich-reflection.js";

export const createAttributedNativeAotScope = () => {
  const scope = createRichNativeAotScope();
  const attribute: NativeAotAttribute = { type: "Example<Attribute>", constructorName: ".ctor",
    fixedArguments: [{ type: "long", value: "9007199254740993" }, { type: "string", value: "<text>" }],
    namedArguments: [{ kind: "property", name: "Enabled", type: "System.Boolean", value: { type: "bool", value: false } }] };
  scope.attributes = [attribute];
  scope.moduleAttributes = [attribute];
  scope.types[0]!.attributes = [attribute];
  scope.types[0]!.definition!.genericParameters[0]!.attributes = [attribute];
  scope.types[0]!.methods[0]!.attributes = [attribute];
  scope.types[0]!.methods[0]!.parameters![0]!.attributes = [attribute];
  scope.types[0]!.methods[0]!.genericParameters![0]!.attributes = [attribute];
  scope.types[0]!.fields[0]!.attributes = [attribute];
  scope.types[0]!.definition!.properties[0]!.attributes = [attribute];
  scope.types[0]!.definition!.events[0]!.attributes = [attribute];
  return scope;
};
