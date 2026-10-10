import { NativeFormatFixtureWriter } from "./native-format-metadata-fixture.js";
import { createNativeFormatSignatureFixture } from "./native-format-signature-fixture.js";

const memberHandleType = {
  constantString: 0x1a, fieldSignature: 0x24, genericParameter: 0x26, method: 0x28,
  methodSemantics: 0x2a, methodSignature: 0x2b, methodVariable: 0x2c,
  parameter: 0x31, propertySignature: 0x34, typeReference: 0x3d
} as const;

// NativeFormat metadata record field order comes from the generated readers; the values below
// use CLI MethodAttributes, ParamAttributes, GenericParamAttributes, and MethodSemantics bits.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderGen.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/cor.h
export const createNativeFormatMemberFixture = () => {
  const signature = createNativeFormatSignatureFixture();
  const writer = new NativeFormatFixtureWriter();
  writer.bytes.splice(0, writer.bytes.length, ...signature.bytes);
  signature.labels.forEach((offset, name) => writer.labels.set(name, offset));
  writer.label("method-member");
  // Method record: Public (mdPublic=6), no implementation flags, then name/signature,
  // one parameter row, one generic method parameter, and no custom attributes.
  writer.unsigned(6);
  writer.unsigned(0);
  writer.handle(memberHandleType.constantString, "method-name");
  writer.handle(memberHandleType.methodSignature, "method");
  writer.collection([[memberHandleType.parameter, "parameter"]]);
  writer.collection([[memberHandleType.genericParameter, "generic"]]);
  writer.unsigned(0);
  writer.label("parameter");
  writer.unsigned(16); // pdOptional: this explicit parameter is optional.
  writer.unsigned(1); // Sequence 1 is the first declared parameter; sequence 0 is the return value.
  writer.handle(memberHandleType.constantString, "parameter-name");
  writer.unsigned(0);
  writer.unsigned(0);
  writer.label("generic");
  writer.unsigned(0);
  writer.unsigned(4); // ReferenceTypeConstraint on this generic parameter.
  writer.unsigned(1); // GenericMethodParameter, not a type-level generic parameter.
  writer.handle(memberHandleType.constantString, "generic-name");
  writer.unsigned(1);
  writer.variantHandle(memberHandleType.typeReference, "type");
  writer.unsigned(0);
  writeField(writer);
  writeProperty(writer);
  writer.label("event");
  writer.unsigned(0);
  writer.handle(memberHandleType.constantString, "event-name");
  writer.variantHandle(memberHandleType.typeReference, "type");
  writer.collection([[memberHandleType.methodSemantics, "event-semantics"]]);
  writer.unsigned(0);
  writer.label("event-semantics");
  writer.unsigned(8); // AddOn semantics bit for the event's add accessor.
  writer.handle(memberHandleType.method, "method-member");
  writer.string("method-name", "Convert");
  writer.string("parameter-name", "input");
  writer.string("generic-name", "T");
  writer.string("field-name", "Value");
  writer.string("property-name", "Item");
  writer.string("event-name", "Changed");
  return { bytes: Uint8Array.from(writer.bytes),
    handle: (name: string, type: number) => ({ type, offset: writer.labels.get(name)! }) };
};

const writeField = (writer: NativeFormatFixtureWriter): void => {
  writer.label("field");
  writer.unsigned(6); // mdPublic; parser preserves the metadata flag value.
  writer.handle(memberHandleType.constantString, "field-name");
  writer.handle(memberHandleType.fieldSignature, "field-signature");
  writer.unsigned(0);
  writer.unsigned(12); // Deliberate field offset value for the decoded member model.
  writer.unsigned(0);
  writer.label("field-signature");
  writer.variantHandle(memberHandleType.typeReference, "type");
};

const writeProperty = (writer: NativeFormatFixtureWriter): void => {
  writer.label("property");
  writer.unsigned(0);
  writer.handle(memberHandleType.constantString, "property-name");
  writer.handle(memberHandleType.propertySignature, "property-signature");
  writer.collection([[memberHandleType.methodSemantics, "property-semantics"]]);
  writer.unsigned(0);
  writer.unsigned(0);
  writer.label("property-signature");
  writer.unsigned(0x20); // SignatureCallingConvention.HasThis.
  writer.variantHandle(memberHandleType.typeReference, "type");
  writer.unsigned(1);
  writer.variantHandle(memberHandleType.methodVariable, "method-variable");
  writer.label("property-semantics");
  writer.unsigned(2); // Getter semantics bit; the member reader preserves the flags verbatim.
  writer.handle(memberHandleType.method, "method-member");
};
