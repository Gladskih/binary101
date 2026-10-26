import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { CodeViewFrame } from "./codeview-local-types.js";

// FRAMEPROCSYM is packed: flags follow the 2-byte handler section at offset 26.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L4069
export const readCodeViewFrame = async (reader: LegacyCodeViewReader, type: number
): Promise<{ frame: CodeViewFrame } | null> => {
  if (type !== 0x1012) return null;
  const fields = await reader.view(4, 26);
  const flags = fields.getUint32(22, true);
  if (flags & 0xff800000) reader.warn("CodeView frame flags contain reserved bits.");
  return { frame: { frameBytes: fields.getUint32(0, true), paddingBytes: fields.getUint32(4, true),
    paddingOffset: fields.getUint32(8, true), savedRegisterBytes: fields.getUint32(12, true),
    handler: { offset: fields.getUint32(16, true), section: fields.getUint16(20, true) }, flags } };
};
