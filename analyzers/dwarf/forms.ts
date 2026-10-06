"use strict";

import type { DwarfCursor } from "./cursor.js";
import {
  DWARF_ENCODING,
  DWARF_FORM,
  DWARF_SECTION,
  DWARF_VERSION
} from "./constants.js";
import type {
  DwarfAbbreviationAttribute,
  DwarfAttribute,
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
  DWARF_FORM.locationListIndex,
  DWARF_FORM.rangeListIndex
]);

// Supplementary strings belong to a different file; never resolve them against this file.
const stringSections = new Map<number, string>([
  [DWARF_FORM.stringPointer, DWARF_SECTION.strings],
  [DWARF_FORM.lineStringPointer, DWARF_SECTION.lineStrings],
  [DWARF_FORM.stringPointerSupplementary, "supplementary .debug_str"],
  [DWARF_FORM.gnuStringPointerAlternate, "supplementary .debug_str"]
]);

const offsetByteLength = (context: DwarfUnitContext): number =>
  context.format / DWARF_ENCODING.bitsPerByte;

const unsignedValue = (value: bigint): DwarfFormValue => ({ kind: "unsigned", value });

const readUnsigned = async (
  cursor: DwarfCursor,
  byteLength: number
): Promise<DwarfFormValue | null> => {
  const value = await cursor.unsigned(byteLength);
  return value == null ? null : unsignedValue(value);
};

const readSizedBlock = async (
  cursor: DwarfCursor,
  lengthBytes: number | "uleb"
): Promise<DwarfFormValue | null> => {
  const length = lengthBytes === "uleb"
    ? await cursor.uleb()
    : await cursor.unsigned(lengthBytes);
  if (length == null) return null;
  const value = await cursor.bytes(length);
  return value == null ? null : { kind: "block", value };
};

const readStringOffset = async (
  cursor: DwarfCursor,
  context: DwarfUnitContext,
  sectionName: string
): Promise<DwarfFormValue | null> => {
  const value = await cursor.unsigned(offsetByteLength(context));
  return value == null ? null : { kind: "string-offset", value, sectionName };
};

const fixedUnsignedBytes = (form: number, context: DwarfUnitContext): number | null => {
  if (form === DWARF_FORM.address) return context.addressSize;
  if (form === DWARF_FORM.referenceAddress) {
    return context.version <= DWARF_VERSION.referenceAddressUsesAddressSizeThrough
      ? context.addressSize
      : offsetByteLength(context);
  }
  if (form === DWARF_FORM.sectionOffset || form === DWARF_FORM.gnuReferenceAlternate) {
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
  return readFlagValue(cursor, attribute);
};

const readFlagValue = async (
  cursor: DwarfCursor, attribute: DwarfAbbreviationAttribute
): Promise<DwarfFormValue | null | undefined> => {
  if (attribute.form === DWARF_FORM.flag) {
    const value = await cursor.uint8();
    return value == null ? null : { kind: "flag", value: value !== 0 };
  }
  if (attribute.form === DWARF_FORM.flagPresent) return { kind: "flag", value: true };
  if (attribute.form === DWARF_FORM.implicitConstant) {
    if (attribute.implicitConstant == null) cursor.fail("Missing implicit constant in abbreviation");
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
  if (form === DWARF_FORM.block2) return readSizedBlock(cursor, Uint16Array.BYTES_PER_ELEMENT);
  if (form === DWARF_FORM.block4) return readSizedBlock(cursor, Uint32Array.BYTES_PER_ELEMENT);
  if (form === DWARF_FORM.block || form === DWARF_FORM.expressionLocation) {
    return readSizedBlock(cursor, "uleb");
  }
  if (form === DWARF_FORM.block1) return readSizedBlock(cursor, Uint8Array.BYTES_PER_ELEMENT);
  if (form === DWARF_FORM.data16) {
    const value = await cursor.bytes(DWARF_ENCODING.data16Bytes);
    return value == null ? null : { kind: "block", value };
  }
  return undefined;
};

const indexedWidths = (form: number): { kind: "string-index" | "address-index"; width: number | "uleb" } | null => {
  if (form === DWARF_FORM.addressIndex || form === DWARF_FORM.gnuAddressIndex) {
    return { kind: "address-index", width: "uleb" };
  }
  if (form === DWARF_FORM.stringIndex || form === DWARF_FORM.gnuStringIndex) {
    return { kind: "string-index", width: "uleb" };
  }
  if (form >= DWARF_FORM.stringIndex1 && form <= DWARF_FORM.stringIndex4) {
    return { kind: "string-index", width: form - DWARF_FORM.stringIndex1 + 1 };
  }
  if (form >= DWARF_FORM.addressIndex1 && form <= DWARF_FORM.addressIndex4) {
    return { kind: "address-index", width: form - DWARF_FORM.addressIndex1 + 1 };
  }
  return null;
};

const readIndexedValue = async (
  cursor: DwarfCursor, form: number
): Promise<DwarfFormValue | null | undefined> => {
  const encoding = indexedWidths(form);
  if (!encoding) return undefined;
  const value = encoding.width === "uleb" ? await cursor.uleb() : await cursor.unsigned(encoding.width);
  return value == null ? null : { kind: encoding.kind, value };
};

const readDirectForm = async (
  cursor: DwarfCursor,
  attribute: DwarfAbbreviationAttribute,
  context: DwarfUnitContext
): Promise<DwarfFormValue | null> => {
  const resolved = attribute;
  const fixedBytes = fixedUnsignedBytes(resolved.form, context);
  if (fixedBytes != null) return readUnsigned(cursor, fixedBytes);
  const stringSection = stringSections.get(resolved.form);
  if (stringSection) return readStringOffset(cursor, context, stringSection);
  const variable = await readVariableValue(cursor, resolved);
  if (variable !== undefined) return variable;
  const block = await readBlock(cursor, resolved.form);
  if (block !== undefined) return block;
  const indexed = await readIndexedValue(cursor, resolved.form);
  if (indexed !== undefined) return indexed;
  cursor.fail(`Unsupported DWARF form 0x${resolved.form.toString(16)}`);
  return null;
};

export const readDwarfAttribute = async (
  cursor: DwarfCursor,
  attribute: DwarfAbbreviationAttribute,
  context: DwarfUnitContext
): Promise<DwarfAttribute | null> => {
  let resolved = attribute;
  while (resolved.form === DWARF_FORM.indirect) {
    const form = await cursor.uleb();
    if (form == null) return null;
    if (form > BigInt(Number.MAX_SAFE_INTEGER)) {
      cursor.fail("Indirect DWARF form cannot be represented exactly");
      return null;
    }
    resolved = { name: resolved.name, form: Number(form), implicitConstant: null };
  }
  const value = await readDirectForm(cursor, resolved, context);
  return value == null ? null : { name: resolved.name, form: resolved.form, value };
};

export const readDwarfForm = async (
  cursor: DwarfCursor,
  attribute: DwarfAbbreviationAttribute,
  context: DwarfUnitContext
): Promise<DwarfFormValue | null> =>
  (await readDwarfAttribute(cursor, attribute, context))?.value ?? null;
