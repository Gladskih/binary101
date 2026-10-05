import { NativeFormatFixtureWriter } from "./native-format-metadata-fixture.js";
import { NativeFormatReader } from "../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatStore } from "../../analyzers/native-aot/native-format-store.js";

const definition = (writer: NativeFormatFixtureWriter, name: string, enclosing?: string): void => {
  writer.label(name);
  writer.unsigned(0);
  writer.unsigned(0);
  writer.handle(0x2f, "namespace");
  writer.handle(0x1a, `${name}-name`);
  writer.unsigned(0);
  writer.unsigned(0);
  writer.handle(0x3a, enclosing);
  // Eight collection fields follow EnclosingType in NativeFormatReaderGen.TypeDefinition.
  for (let index = 0; index < 8; index += 1) writer.unsigned(0);
};

export const createNativeFormatTypeNodeFixture = () => {
  const writer = new NativeFormatFixtureWriter();
  definition(writer, "outer");
  definition(writer, "inner", "outer");
  writer.label("namespace");
  writer.unsigned(0);
  writer.handle(0x1a, "namespace-name");
  writer.unsigned(0);
  writer.unsigned(0);
  writer.unsigned(0);
  writer.string("outer-name", "Outer");
  writer.string("inner-name", "Inner");
  writer.string("namespace-name", "Demo");
  const warnings = new Set<string>();
  return { store: new NativeFormatStore(new NativeFormatReader(Uint8Array.from(writer.bytes)), warnings),
    warnings, handle: (name: string, type: number) => ({ type, offset: writer.labels.get(name)! }) };
};
