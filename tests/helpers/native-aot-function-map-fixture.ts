import { NativeFormatReader } from "../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatCursor } from "../../analyzers/native-aot/native-format-cursor.js";
import { NativeAotCodeReferences } from "../../analyzers/native-aot/code-references.js";
import { createNativeAotInvokeFixture } from "./native-aot-invoke-fixture.js";
import { createNativeHashtableFixture } from "./native-hashtable-fixture.js";

export const createNativeAotFunctionMapFixture = (type: number, payloads: Uint8Array[]) => {
  const fixture = createNativeAotInvokeFixture();
  const map = createNativeHashtableFixture(payloads);
  fixture.bytes.set(map, fixture.mapRva);
  fixture.sections[0] = { type, rva: fixture.mapRva, size: map.length };
  return fixture;
};

export const createFunctionEntryFixture = (bytes: Uint8Array) => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();
  return { ...fixture, issues, cursor: new NativeFormatCursor(new NativeFormatReader(bytes), 0),
    references: new NativeAotCodeReferences(fixture.image, fixture.sections, issues) };
};

export const createNativeAotTemplateFixture = () => {
  const fixture = createNativeAotFunctionMapFixture(322, [Uint8Array.of(0, 12)]);
  // NativeLayout MethodFlags: HasInstantiation=1, HasFunctionPointer=4.
  // TypeSignatureKind.External=6; NativeFormat unsigned integers are doubled below 128.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormat.cs
  fixture.bytes.set([10, 0, 12, 20, 2, 44, 0], 0x340);
  fixture.view.setInt32(0x220, fixture.codeRvas[1]! - 0x220, true);
  fixture.view.setInt32(0x224, fixture.codeRvas[0]! - 0x224, true);
  fixture.sections.push({ type: 330, rva: 0x340, size: 7 }, { type: 331, rva: 0x220, size: 8 });
  return fixture;
};
