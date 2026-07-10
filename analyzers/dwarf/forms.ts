"use strict";

import type { DwarfCursor } from "./cursor.js";
import {
  DWARF_ENCODING,
  DWARF_FORM,
  DWARF_LIMIT,
  DWARF_SECTION,
  DWARF_VERSION
} from "./constants.js";
import type {
  DwarfAbbreviationAttribute,
  DwarfFormValue,
  DwarfUnitContext
} from "./types.js";

// Form encodings and operand widths follow DWARF 5, section 7.5.4, Table 7.5:
// https://dwarfstd.org/doc/DWARF5.pdf

const FIXED_FORM_BYTE_LENGTHS = new Map<number, number>([
  [DWARF_FORM.data1, Uint8Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.reference1, Uint8Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.data2, Uint16Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.reference2, Uint16Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.data4, Uint32Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.reference4, Uint32Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.referenceSupplementary4, Uint32Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.data8, BigUint64Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.reference8, BigUint64Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.referenceSignature8, BigUint64Array.BYTES_PER_ELEMENT],
  [DWARF_FORM.referenceSupplementary8, BigUint64Array.BYTES_PER_ELEMENT]
]);

const ULEB_FORMS = new Set<number>([
  DWARF_FORM.unsignedData,
  DWARF_FORM.referenceUnsigned,
  DWARF_FORM.addressIndex,
  DWARF_FORM.locationListIndex,
  DWARF_FORM.rangeListIndex
]);

const offsetByteLength = (context: DwarfUnitContext): number =>
  context.format / DWARF_ENCODING.bitsPerByte;

const emptyValue = (): DwarfFormValue => ({ kind: "empty" });
const unsignedValue = (value: bigint): DwarfFormValue => ({ kind: "unsigned", value });

const readUnsigned = async (
  cursor: DwarfCursor,
  byteLength: number
): Promise<DwarfFormValue | null> => {
  const value = await cursor.unsigned(byteLength);
  return value == null ? null : unsignedValue(value);
};

const skipBlock = async (
  cursor: DwarfCursor,
  lengthBytes: number | "uleb"
): Promise<DwarfFormValue | null> => {
  const length = lengthBytes === "uleb"
    ? await cursor.uleb()
    : await cursor.unsigned(lengthBytes);
  return length != null && cursor.skip(length) ? emptyValue() : null;
};

const readStringOffset = async (
  cursor: DwarfCursor,
  context: DwarfUnitContext,
  sectionName: string
): Promise<DwarfFormValue | null> => {
  const value = await cursor.unsigned(offsetByteLength(context));
  return value == null ? null : { kind: "string-offset", value, sectionName };
};

const readStringIndex = async (
  cursor: DwarfCursor,
  byteLength: number | "uleb"
): Promise<DwarfFormValue | null> => {
  const value = byteLength === "uleb"
    ? await cursor.uleb()
    : await cursor.unsigned(byteLength);
  return value == null ? null : { kind: "string-index", value };
};

const fixedUnsignedBytes = (form: number, context: DwarfUnitContext): number | null => {
  if (form === DWARF_FORM.address) return context.addressSize;
  if (form === DWARF_FORM.referenceAddress) {
    return context.version <= DWARF_VERSION.referenceAddressUsesAddressSizeThrough
      ? context.addressSize
      : offsetByteLength(context);
  }
  if (form === DWARF_FORM.sectionOffset || form === DWARF_FORM.stringPointerSupplementary) {
    return offsetByteLength(context);
  }
  return FIXED_FORM_BYTE_LENGTHS.get(form) ?? null;
};

const readVariableValue = async (
  cursor: DwarfCursor,
  attribute: DwarfAbbreviationAttribute
): Promise<DwarfFormValue | null | undefined> => {
  if (attribute.form === DWARF_FORM.string) {
    const value = await cursor.cstring();
    return value == null ? null : { kind: "string", value };
  }
  if (attribute.form === DWARF_FORM.signedData) {
    const value = await cursor.sleb();
    return value == null ? null : { kind: "signed", value };
  }
  if (ULEB_FORMS.has(attribute.form)) {
    const value = await cursor.uleb();
    return value == null ? null : unsignedValue(value);
  }
  if (attribute.form === DWARF_FORM.flag) {
    const value = await cursor.uint8();
    return value == null ? null : { kind: "flag", value: value !== 0 };
  }
  if (attribute.form === DWARF_FORM.flagPresent) return { kind: "flag", value: true };
  if (attribute.form === DWARF_FORM.implicitConstant) {
    return attribute.implicitConstant == null
      ? null
      : { kind: "signed", value: attribute.implicitConstant };
  }
  return undefined;
};

const readBlock = async (
  cursor: DwarfCursor,
  form: number
): Promise<DwarfFormValue | null | undefined> => {
  if (form === DWARF_FORM.block2) return skipBlock(cursor, Uint16Array.BYTES_PER_ELEMENT);
  if (form === DWARF_FORM.block4) return skipBlock(cursor, Uint32Array.BYTES_PER_ELEMENT);
  if (form === DWARF_FORM.block || form === DWARF_FORM.expressionLocation) {
    return skipBlock(cursor, "uleb");
  }
  if (form === DWARF_FORM.block1) return skipBlock(cursor, Uint8Array.BYTES_PER_ELEMENT);
  if (form === DWARF_FORM.data16) {
    return cursor.skip(DWARF_ENCODING.data16Bytes) ? emptyValue() : null;
  }
  return undefined;
};

const readIndexedValue = async (
  cursor: DwarfCursor,
  form: number
): Promise<DwarfFormValue | null | undefined> => {
  if (form === DWARF_FORM.stringIndex || form === DWARF_FORM.gnuStringIndex) {
    return readStringIndex(cursor, "uleb");
  }
  if (form >= DWARF_FORM.stringIndex1 && form <= DWARF_FORM.stringIndex4) {
    return readStringIndex(
      cursor,
      form - DWARF_FORM.stringIndex1 + Uint8Array.BYTES_PER_ELEMENT
    );
  }
  if (form >= DWARF_FORM.addressIndex1 && form <= DWARF_FORM.addressIndex4) {
    return readUnsigned(
      cursor,
      form - DWARF_FORM.addressIndex1 + Uint8Array.BYTES_PER_ELEMENT
    );
  }
  if (form === DWARF_FORM.gnuAddressIndex) {
    const value = await cursor.uleb();
    return value == null ? null : unsignedValue(value);
  }
  return undefined;
};

export const readDwarfForm = async (
  cursor: DwarfCursor,
  attribute: DwarfAbbreviationAttribute,
  context: DwarfUnitContext,
  indirectDepth = 0
): Promise<DwarfFormValue | null> => {
  const fixedBytes = fixedUnsignedBytes(attribute.form, context);
  if (fixedBytes != null) return readUnsigned(cursor, fixedBytes);
  if (attribute.form === DWARF_FORM.stringPointer) {
    return readStringOffset(cursor, context, DWARF_SECTION.strings);
  }
  if (attribute.form === DWARF_FORM.lineStringPointer) {
    return readStringOffset(cursor, context, DWARF_SECTION.lineStrings);
  }
  const variable = await readVariableValue(cursor, attribute);
  if (variable !== undefined) return variable;
  const block = await readBlock(cursor, attribute.form);
  if (block !== undefined) return block;
  const indexed = await readIndexedValue(cursor, attribute.form);
  if (indexed !== undefined) return indexed;
  if (attribute.form === DWARF_FORM.indirect &&
      indirectDepth < DWARF_LIMIT.maximumIndirectFormDepth) {
    const form = await cursor.uleb();
    if (form == null || form > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    return readDwarfForm(
      cursor,
      { name: attribute.name, form: Number(form), implicitConstant: null },
      context,
      indirectDepth + 1
    );
  }
  cursor.fail(`Unsupported DWARF form 0x${attribute.form.toString(16)}`);
  return null;
};
