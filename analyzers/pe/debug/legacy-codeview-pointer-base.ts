import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readLegacyCodeViewEmbeddedSymbol, type LegacyCodeViewSymbol } from "./legacy-codeview-symbol-records.js";

// LF_POINTER_16t stores WORD attributes then a WORD type index; LF_POINTER
// stores a DWORD type index then DWORD attributes. Pointer-to-member modes
// select a different union arm, even when ptrtype happens to be CV_PTR_BASE_TYPE.
// TIS 3.3 Pointer; Microsoft's lfPointer, CV_ptrtype_e and CV_ptrmode_e:
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L1472
const POINTER_LAYOUTS = {
  2: { prefix: 8, attributes: 4, indexSize: 2, maximumMode: 3, maximumKind: 11 },
  0x1002: { prefix: 12, attributes: 8, indexSize: 4, maximumMode: 4, maximumKind: 12 }
};

export const readLegacyCodeViewPointerBase = async (
  reader: LegacyCodeViewReader, type: 2 | 0x1002
): Promise<{ strings?: string[]; symbols?: LegacyCodeViewSymbol[] }> => {
  const layout = POINTER_LAYOUTS[type];
  const attributes = (await reader.view(0, layout.prefix)).getUint16(layout.attributes, true);
  const mode = attributes >>> 5 & 7;
  const kind = attributes & 31;
  if (mode > layout.maximumMode || kind > layout.maximumKind) {
    reader.warn("CodeView pointer uses a reserved kind or mode; its base was not decoded.");
    return {};
  }
  if (mode === 2 || mode === 3) {
    await reader.view(layout.prefix, layout.indexSize + 2);
    return {};
  }
  if (kind === 3) await reader.view(layout.prefix, 2);
  if (kind === 8) return { strings: [(await reader.pascal(layout.prefix + layout.indexSize)).name] };
  if (kind >= 4 && kind <= 7) return { symbols: await readLegacyCodeViewEmbeddedSymbol(reader, layout.prefix) };
  return {};
};
