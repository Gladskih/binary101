import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { CodeViewLocalRange } from "./codeview-local-types.js";
import { readCodeViewShaderRange } from "./codeview-shader-ranges.js";

// DEFRANGESYM through DEFRANGESYMREGISTERREL; all fixed fields and gap arrays
// are naturally four-byte sized, so a partial gap is not alignment padding.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L4188
const prefixes = new Map([[0x113f, 8], [0x1140, 12], [0x1141, 8], [0x1142, 8],
  [0x1143, 12], [0x1144, 8], [0x1145, 12], [0x1177, 16]]);

const readLocation = (fields: DataView, type: number): CodeViewLocalRange => {
  const gaps: CodeViewLocalRange["gaps"] = [];
  if (type === 0x113f || type === 0x1140) return {
    location: { kind: "program", program: fields.getUint32(0, true) }, gaps,
    ...(type === 0x1140 ? { parentOffset: fields.getUint32(4, true) } : {}) };
  if (type === 0x1142 || type === 0x1144) return {
    location: { kind: "frameRelative", offset: fields.getInt32(0, true) }, gaps };
  const register = fields.getUint16(0, true);
  const attributes = fields.getUint16(2, true);
  // LLVM's indirect range adds a signed member offset after dereferencing the base.
  // https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/include/llvm/DebugInfo/CodeView/SymbolRecord.h#L593
  if (type === 0x1177) return { location: { kind: "registerIndirectRelative", register,
    offset: fields.getInt32(4, true), memberOffset: fields.getInt32(8, true) }, attributes, gaps };
  if (type === 0x1145) return { location: { kind: "registerRelative", register,
    offset: fields.getInt32(4, true) }, attributes, gaps };
  return { location: { kind: "register", register }, attributes, gaps,
    ...(type === 0x1143 ? { parentOffset: fields.getUint32(4, true) } : {}) };
};

const validateAttributes = (reader: LegacyCodeViewReader, type: number, info: CodeViewLocalRange): void => {
  // REGISTER_REL packs spilled-member in bit 0 and parent offset in bits 4-15.
  const reserved = type === 0x1145 || type === 0x1177 ? 0x000e : 0xfffe;
  if (info.attributes !== undefined && info.attributes & reserved) reader.warn("CodeView local range attributes contain reserved bits.");
  if (type === 0x1143 && info.parentOffset! > 0xfff) reader.warn("CodeView subfield offset contains reserved bits.");
};

const readGaps = async (reader: LegacyCodeViewReader, start: number, end: number,
  info: CodeViewLocalRange): Promise<void> => {
  let previousEnd = 0;
  for (let offset = start; offset + 4 <= end; offset += 4) {
    const fields = await reader.view(offset, 4);
    const gap = { offset: fields.getUint16(0, true), length: fields.getUint16(2, true) };
    info.gaps.push(gap);
    if (gap.offset + gap.length > info.range!.length) reader.warn("CodeView local gap exceeds its live range.");
    if (gap.offset < previousEnd) reader.warn("CodeView local gaps overlap or are not ordered.");
    previousEnd = gap.offset + gap.length;
  }
  if ((end - start) % 4) reader.warn("CodeView local range ends with a truncated gap.");
};

const readRangePrefix = async (reader: LegacyCodeViewReader, type: number
): Promise<{ localRange: CodeViewLocalRange; prefix: number; gapEnd: number } | null> => {
  const shader = await readCodeViewShaderRange(reader, type);
  if (shader) return shader;
  const prefix = prefixes.get(type);
  if (prefix === undefined) return null;
  return { localRange: readLocation(await reader.view(4, prefix - 4), type), prefix, gapEnd: reader.size };
};

const readRangeBody = async (reader: LegacyCodeViewReader, prefix: number, gapEnd: number,
  localRange: CodeViewLocalRange): Promise<void> => {
  try {
    const range = await reader.view(prefix, 8);
    localRange.range = { offset: range.getUint32(0, true), section: range.getUint16(4, true),
      length: range.getUint16(6, true) };
    if (localRange.range.offset + localRange.range.length > 0x100000000) {
      reader.warn("CodeView local range exceeds 32-bit section offsets.");
    }
    // CV_LEXICAL_RANGE_MAX reserves cbRange >= 0xf000 for other encodings.
    if (localRange.range.length >= 0xf000) reader.warn("CodeView local range uses a reserved length encoding.");
    await readGaps(reader, prefix + 8, gapEnd, localRange);
  } catch (error) { reader.warn(`CodeView local range: ${String(error)}`); }
};

export const readCodeViewLocalRange = async (reader: LegacyCodeViewReader, type: number
): Promise<{ localRange: CodeViewLocalRange } | null> => {
  const parsed = await readRangePrefix(reader, type);
  if (!parsed) return null;
  const { localRange, prefix, gapEnd } = parsed;
  validateAttributes(reader, type, localRange);
  if (type === 0x1144) {
    if (reader.size !== prefix) reader.warn("CodeView full-scope local range has unexpected trailing bytes.");
  } else await readRangeBody(reader, prefix, gapEnd, localRange);
  return { localRange };
};
