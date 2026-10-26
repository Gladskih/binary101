import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { CodeViewLocalRange } from "./codeview-local-types.js";

// DEFRANGESYMHLSL is shared by S_DEFRANGE_HLSL and S_DEFRANGE_DPC_PTR_TAG.
// regIndices counts trailing u32 register offsets after the CV_LVAR_ADDR_GAP array.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L4293
export const readCodeViewShaderRange = async (reader: LegacyCodeViewReader, type: number
): Promise<{ localRange: CodeViewLocalRange; prefix: number; gapEnd: number } | null> => {
  if (type !== 0x1150 && type !== 0x1157) return null;
  const fields = await reader.view(4, 8);
  const attributes = fields.getUint16(2, true);
  const dimensions = attributes & 3;
  if (dimensions === 3) reader.warn("CodeView shader register dimensionality is reserved.");
  if (attributes & 0xff80) reader.warn("CodeView shader range attributes contain reserved bits.");
  const location: Extract<CodeViewLocalRange["location"], { kind: "shaderRegister" }> = {
    kind: "shaderRegister", registerType: fields.getUint16(0, true), attributes };
  const localRange: CodeViewLocalRange = { location, parentOffset: fields.getUint16(4, true),
    sizeInParent: fields.getUint16(6, true), gaps: [] };
  const gapEnd = reader.size - dimensions * 4;
  // The 20-byte fixed record includes the eight-byte address range. Missing
  // index bytes cannot be distinguished from a truncated gap list: do not guess.
  if (gapEnd < 20) {
    reader.warn("CodeView shader register offsets are truncated.");
    return { localRange, prefix: 12, gapEnd: 20 };
  }
  const offsets = await reader.view(gapEnd, dimensions * 4);
  location.registerOffsets = Array.from({ length: dimensions }, (_, index) => offsets.getUint32(index * 4, true));
  return { localRange, prefix: 12, gapEnd };
};
