import { readLegacyCodeViewNumeric } from "./legacy-codeview-numeric.js";
import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface LegacyCodeViewConstantNumeric {
  byteLength: number;
  leaf?: number;
  value?: string;
}

export interface LegacyCodeViewConstant {
  typeIndex?: number;
  numeric: LegacyCodeViewConstantNumeric | { issue: string };
}

interface ConstantLayout {
  typeIndexBytes: 2 | 4;
  nameEncoding: "ansi" | "utf8";
}

// Microsoft cvinfo.h CONSTSYM_16t and CONSTSYM layouts; offsets include
// reclen and rectyp. https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const CONSTANT_LAYOUTS = new Map<number, ConstantLayout>([
  [0x0003, { typeIndexBytes: 2, nameEncoding: "ansi" }],
  [0x1002, { typeIndexBytes: 4, nameEncoding: "ansi" }],
  [0x1107, { typeIndexBytes: 4, nameEncoding: "utf8" }]
]);

const readTypeIndex = async (reader: LegacyCodeViewReader, width: 2 | 4): Promise<number> =>
  width === 2 ? reader.uint16(4) : reader.uint32(4);

const readConstantName = async (reader: LegacyCodeViewReader, offset: number,
  encoding: ConstantLayout["nameEncoding"]): Promise<string> => encoding === "utf8"
  ? reader.utf8(offset) : (await reader.pascal(offset)).name;

/** Read the constant type, numeric leaf and trailing name from one record-local byte range. */
export const readLegacyCodeViewConstantSymbol = async (
  reader: LegacyCodeViewReader, type: number
): Promise<{ name?: string; constant: LegacyCodeViewConstant } | null> => {
  const layout = CONSTANT_LAYOUTS.get(type);
  if (!layout) return null;
  let typeIndex: number | undefined;
  try { typeIndex = await readTypeIndex(reader, layout.typeIndexBytes); }
  catch (error) { reader.warn(`CodeView constant type reference: ${String(error)}`); }
  const numericOffset = 4 + layout.typeIndexBytes;
  let nameOffset: number | undefined;
  let numeric: LegacyCodeViewConstantNumeric | { issue: string };
  try {
    const { end, leaf, value } = await readLegacyCodeViewNumeric(reader, numericOffset);
    numeric = { byteLength: end - numericOffset, ...(leaf === undefined ? {} : { leaf }),
      ...(value === undefined ? {} : { value }) };
    nameOffset = end;
  } catch (error) {
    const issue = String(error);
    numeric = { issue };
    reader.warn(`CodeView constant numeric value: ${issue}`);
  }
  const constant: LegacyCodeViewConstant = { ...(typeIndex === undefined ? {} : { typeIndex }), numeric };
  if (nameOffset === undefined) return { constant };
  try {
    return { name: await readConstantName(reader, nameOffset, layout.nameEncoding),
      constant };
  } catch (error) {
    reader.warn(`CodeView constant name: ${String(error)}`);
    return { constant };
  }
};
