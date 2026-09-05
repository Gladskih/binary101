import { NativeFormatReader } from "../../analyzers/native-aot/native-format-reader.js";
import {
  parseNativeFormatScopeRecord,
  parseNativeFormatNamespaceRecord,
  parseNativeFormatTypeRecord
} from "../../analyzers/native-aot/native-format-records.js";
import { createNativeFormatMetadataFixture } from "./native-format-metadata-fixture.js";

const readFixtureRootNamespace = (reader: NativeFormatReader) =>
  // Typed handle IDs and NativeFormat root offset from NativeFormatReaderCommonGen.cs.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
  parseNativeFormatNamespaceRecord(reader,
    parseNativeFormatScopeRecord(reader, reader.handles(4, [0x38]).value[0]!).rootNamespace);

export const createNativeFormatFieldFixture = () => {
  const bytes = createNativeFormatMetadataFixture();
  const reader = new NativeFormatReader(bytes);
  const type = parseNativeFormatTypeRecord(reader,
    parseNativeFormatNamespaceRecord(reader, readFixtureRootNamespace(reader).children[0]!).types[0]!);
  return { bytes, reader, type, fields: reader.handles(type.fieldsOffset, [0x23]).value };
};

export const patchNativeFormatFieldSlot = (bytes: Uint8Array, slot: number, value: number): void => {
  // The fixture writer reserves the five-byte unsigned encoding for every typed handle.
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(slot + 1, value, true);
};
