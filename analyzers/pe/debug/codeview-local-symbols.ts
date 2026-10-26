import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { CodeViewLocalVariable, CodeViewVariableLocation } from "./codeview-local-types.js";

interface LocalLayout {
  nameOffset: number;
  typeOffset: number;
  typeBytes: 2 | 4;
  offsetBytes?: 2 | 4;
  registerOffset?: number;
  flagsOffset?: number;
  moduleOffset?: number;
}

// REGSYM, BPRELSYM and REGREL layouts, followed by LOCALSYM/FILESTATICSYM.
// Offsets include reclen/rectyp. BPREL uses signed offsets; REGREL stores unsigned offsets.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/include/llvm/DebugInfo/CodeView/SymbolRecord.h
const LAYOUTS = new Map<number, LocalLayout>([
  [0x0002, { nameOffset: 8, typeOffset: 4, typeBytes: 2, registerOffset: 6 }],
  [0x1001, { nameOffset: 10, typeOffset: 4, typeBytes: 4, registerOffset: 8 }],
  [0x1106, { nameOffset: 10, typeOffset: 4, typeBytes: 4, registerOffset: 8 }],
  [0x0100, { nameOffset: 8, typeOffset: 6, typeBytes: 2, offsetBytes: 2 }],
  [0x0200, { nameOffset: 10, typeOffset: 8, typeBytes: 2, offsetBytes: 4 }],
  [0x1006, { nameOffset: 12, typeOffset: 8, typeBytes: 4, offsetBytes: 4 }],
  [0x110b, { nameOffset: 12, typeOffset: 8, typeBytes: 4, offsetBytes: 4 }],
  [0x010c, { nameOffset: 10, typeOffset: 8, typeBytes: 2, offsetBytes: 2, registerOffset: 6 }],
  [0x020c, { nameOffset: 12, typeOffset: 10, typeBytes: 2, offsetBytes: 4, registerOffset: 8 }],
  [0x100d, { nameOffset: 14, typeOffset: 8, typeBytes: 4, offsetBytes: 4, registerOffset: 12 }],
  [0x1111, { nameOffset: 14, typeOffset: 8, typeBytes: 4, offsetBytes: 4, registerOffset: 12 }],
  [0x113e, { nameOffset: 10, typeOffset: 4, typeBytes: 4, flagsOffset: 8 }],
  [0x1153, { nameOffset: 14, typeOffset: 4, typeBytes: 4, moduleOffset: 8, flagsOffset: 12 }]
]);

const location = (fields: DataView, layout: LocalLayout): CodeViewVariableLocation | undefined => {
  const register = layout.registerOffset === undefined ? undefined : fields.getUint16(layout.registerOffset - 4, true);
  if (layout.offsetBytes === undefined) return register === undefined ? undefined : { kind: "register", register };
  if (register !== undefined) return { kind: "registerOffset", register,
    offset: layout.offsetBytes === 2 ? fields.getUint16(0, true) : fields.getUint32(0, true) };
  const offset = layout.offsetBytes === 2 ? fields.getInt16(0, true) : fields.getInt32(0, true);
  return { kind: "frameRelative", offset };
};

const readFixedLocal = (fields: DataView, layout: LocalLayout): CodeViewLocalVariable => {
  const typeIndex = layout.typeBytes === 2 ? fields.getUint16(layout.typeOffset - 4, true)
    : fields.getUint32(layout.typeOffset - 4, true);
  const placement = location(fields, layout);
  return { typeIndex, ...(placement ? { location: placement } : {}),
    ...(layout.flagsOffset === undefined ? {} : { flags: fields.getUint16(layout.flagsOffset - 4, true) }),
    ...(layout.moduleOffset === undefined ? {} : { moduleOffset: fields.getUint32(layout.moduleOffset - 4, true) }) };
};

export const readCodeViewLocal = async (reader: LegacyCodeViewReader, type: number
): Promise<{ name?: string; local: CodeViewLocalVariable } | null> => {
  const layout = LAYOUTS.get(type);
  if (!layout) return null;
  const local = readFixedLocal(await reader.view(4, layout.nameOffset - 4), layout);
  if (local.flags !== undefined && local.flags & 0xf800) reader.warn("CodeView local flags contain reserved bits.");
  try {
    const name = type >= 0x1100 ? await reader.utf8(layout.nameOffset) : (await reader.pascal(layout.nameOffset)).name;
    return { name, local };
  } catch (error) { reader.warn(`CodeView local name: ${String(error)}`); return { local }; }
};
