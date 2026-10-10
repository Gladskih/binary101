import { NativeFormatReader } from "../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatCursor } from "../../analyzers/native-aot/native-format-cursor.js";

export const createLegacyLayoutCursor = (bytes: Uint8Array): NativeFormatCursor =>
  new NativeFormatCursor(new NativeFormatReader(bytes, "dotnet9"), 0);

export const createLegacyDictionaryFixture = () => {
  // FieldLdToken=7 and MethodLdToken=8 point to separate signatures; GenericStaticConstrainedMethod=34
  // stores an inline constraint followed by a relative method signature (.NET 9 GenericDictionaryCell.cs).
  const bytes = Uint8Array.of(8, 14, 15, 0, 0, 0, 0, 16, 15, 0, 0, 0, 0,
    68, 12, 15, 0, 0, 0, 0, 26, 26, 0, 12, 2, 77, 15, 0, 0, 0, 0, 2, 44,
    12, 2, 70, 0, 24, 2, 12, 2, 77, 15, 0, 0, 0, 0, 0);
  const view = new DataView(bytes.buffer);
  for (const [field, target] of [[2, 33], [8, 37], [15, 37], [26, 47], [42, 47]] as const) {
    view.setInt32(field + 1, target - field, true);
  }
  return { bytes, cursor: createLegacyLayoutCursor(bytes), issues: new Set<string>() };
};
