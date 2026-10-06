import type { NativeFormatCursor } from "./native-format-cursor.js";
import type { NativeAotCodeReferences } from "./code-references.js";
import type { NativeAotStructMarshallingEntry } from "./function-map-types.js";

const readFields = (cursor: NativeFormatCursor, count: number, issues: Set<string>) => {
  const fields: { name: string; offset: number }[] = [];
  // Each field needs at least its string length and offset integers.
  const available = Math.min(count, Math.floor((cursor.reader.size - cursor.offset) / 2));
  if (available < count) issues.add("Struct marshalling field table is truncated.");
  try {
    for (let index = 0; index < available; index += 1) {
      fields.push({ name: cursor.string(), offset: cursor.unsigned() });
    }
  } catch (error) { issues.add(error instanceof Error ? error.message : "Struct field decoding failed."); }
  return fields;
};

// Tuple and InteropDataConstants: type, field-count/flags, optional size/thunks, field names/offsets.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/StructMarshallingStubMapNode.cs
export const readStructMarshallingEntry = async (
  cursor: NativeFormatCursor, references: NativeAotCodeReferences, issues: Set<string>
): Promise<NativeAotStructMarshallingEntry> => {
  const typeIndex = cursor.unsigned();
  references.validateDataIndex(typeIndex);
  const header = cursor.unsigned();
  const entry: NativeAotStructMarshallingEntry = { typeIndex, header,
    marshalRva: null, unmarshalRva: null, cleanupRva: null, fields: [] };
  if (header & 2) {
    if (header !== 2) issues.add("Invalid-layout struct entry has inconsistent marshalling flags or fields.");
    return entry;
  }
  if (header & 1) {
    entry.nativeSize = cursor.unsigned();
    const marshal = cursor.unsigned(), unmarshal = cursor.unsigned(), cleanup = cursor.unsigned();
    entry.marshalRva = await references.resolve(marshal);
    entry.unmarshalRva = await references.resolve(unmarshal);
    entry.cleanupRva = await references.resolve(cleanup);
  }
  entry.fields = readFields(cursor, header >>> 2, issues);
  return entry;
};
