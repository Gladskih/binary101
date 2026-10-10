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
  // Hash tuple uses signature offset 0 and layout offset 6.
  const fixture = createNativeAotFunctionMapFixture(322, [Uint8Array.of(0, 12)]);
  const nativeLayoutRva = 0x340;
  const nativeReferencesRva = 0x220;
  // NativeLayout MethodFlags: HasInstantiation=1, HasFunctionPointer=4.
  // TypeSignatureKind.External=6; NativeFormat unsigned integers are doubled below 128.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormat.cs
  // Signature fields: flags 5, entrypoint index 0, external type index 0, method token 10,
  // one generic type argument (index 1), then a zero-valued end-of-bag marker.
  const templateSignature = Uint8Array.of(10, 0, 12, 20, 2, 44);
  // Signature fields: flags 5, entrypoint index 0, external type index 0, token 10,
  // one generic type argument (index 1). The zero byte terminates its following bag.
  const layoutBytes = Uint8Array.from([...templateSignature, 0]);
  fixture.bytes.set(layoutBytes, nativeLayoutRva);
  // NativeReferences slot 0 targets codeRvas[1]; slot 1 targets codeRvas[0].
  fixture.view.setInt32(nativeReferencesRva, fixture.codeRvas[1]! - nativeReferencesRva, true);
  fixture.view.setInt32(nativeReferencesRva + 4, fixture.codeRvas[0]! - nativeReferencesRva - 4, true);
  fixture.sections.push({ type: 330, rva: nativeLayoutRva, size: layoutBytes.length },
    { type: 331, rva: nativeReferencesRva, size: 4 * fixture.codeRvas.length });
  return { ...fixture, layoutRva: nativeLayoutRva,
    templateSignatureLength: templateSignature.length };
};
