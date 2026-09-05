import { NativeFormatReader } from "../../analyzers/native-aot/native-format-reader.js";
import {
  parseNativeFormatNamespaceRecord, parseNativeFormatScopeRecord, parseNativeFormatTypeRecord
} from "../../analyzers/native-aot/native-format-records.js";
import { createNativeFormatMetadataFixture } from "./native-format-metadata-fixture.js";
import { patchNativeFormatFieldSlot } from "./native-format-field-fixture.js";

const namespaceChildrenOffset = (reader: NativeFormatReader, offset: number): number => {
  // NamespaceDefinition: parent, name, types, forwarders, children.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderGen.cs
  let cursor = reader.handle(offset, [0x2f, 0x38]).nextOffset;
  cursor = reader.handle(cursor, [0x1a]).nextOffset;
  cursor = reader.handles(cursor, [0x3a]).nextOffset;
  return reader.handles(cursor, [0x3b]).nextOffset;
};

const writeUnsignedSequence = (bytes: Uint8Array, offset: number, values: number[]): void => {
  values.forEach((value, index) => {
    bytes[offset + index * 5] = 0x0f; // NativePrimitiveDecoder's five-byte unsigned encoding.
    patchNativeFormatFieldSlot(bytes, offset + index * 5, value);
  });
};

export const createNativeFormatTraversalFixture = (
  kind: "type" | "namespace", names: string[]
) => {
  const original = createNativeFormatMetadataFixture();
  const reader = new NativeFormatReader(original);
  const demo = parseNativeFormatNamespaceRecord(reader,
    parseNativeFormatScopeRecord(reader, reader.handles(4, [0x38]).value[0]!).rootNamespace).children[0]!;
  const program = parseNativeFormatTypeRecord(reader,
    parseNativeFormatNamespaceRecord(reader, demo).types[0]!);
  // Program has one method and one nested type, each encoded as count byte + five-byte handle.
  const childList = kind === "type" ? program.fieldsOffset - 12 : namespaceChildrenOffset(reader, demo.offset);
  const childSlot = reader.collectionCount(childList).nextOffset;
  const next = reader.handle(childSlot, [0x3a]).value.offset;
  // TypeDefinition has 11 encoded values through fields; NamespaceDefinition has 6 through children.
  const stride = (kind === "type" ? 11 : 6) * 5;
  const strings = names.map(name => new TextEncoder().encode(name));
  let stringOffset = original.length + names.length * stride;
  const bytes = new Uint8Array(stringOffset + strings.reduce((size, name) => size + 5 + name.length, 0));
  bytes.set(original);
  patchNativeFormatFieldSlot(bytes, childSlot, original.length);
  for (let index = 0; index < names.length; index += 1) {
    const target = index === names.length - 1 ? next : original.length + (index + 1) * stride;
    writeUnsignedSequence(bytes, original.length + index * stride, kind === "type"
      ? [0, 0, 0, stringOffset, 0, 0, 0, 1, target, 0, 0] : [0, stringOffset, 0, 0, 1, target]);
    writeUnsignedSequence(bytes, stringOffset, [strings[index]!.length]);
    bytes.set(strings[index]!, stringOffset + 5);
    stringOffset += 5 + strings[index]!.length;
  }
  return bytes;
};
