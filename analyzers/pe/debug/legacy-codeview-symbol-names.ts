import { skipLegacyCodeViewNumeric } from "./legacy-codeview-numeric.js";
import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

// Offsets include reclen + rectyp; records before S_ST_MAX use counted ANSI names.
// All layouts and IDs are from Microsoft's CV4, 32-bit type-index and SZ structs.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const NAME_OFFSETS = new Map<number, number>([
  [0x0001, 8], [0x0002, 8], [0x0004, 6], [0x0009, 8], [0x000b, 6],
  [0x0100, 8], [0x0101, 10], [0x0102, 10], [0x0103, 10], [0x0104, 29], [0x0105, 29],
  [0x0106, 23], [0x0107, 18], [0x0108, 18], [0x0109, 9], [0x010c, 10],
  [0x0200, 10], [0x0201, 12], [0x0202, 12], [0x0203, 12], [0x0204, 37], [0x0205, 37],
  [0x0206, 25], [0x0207, 22], [0x0208, 22], [0x0209, 11], [0x020c, 12], [0x020d, 12], [0x020e, 12],
  [0x0300, 54], [0x0301, 54],
  [0x1001, 10], [0x1003, 8], [0x1004, 8], [0x1006, 12], [0x1007, 14], [0x1008, 14],
  [0x1009, 14], [0x100a, 39], [0x100b, 39], [0x100d, 14], [0x100e, 14], [0x100f, 14],
  [0x1010, 56], [0x1011, 56], [0x1013, 22], [0x1015, 41], [0x1016, 41],
  [0x1017, 12], [0x1018, 12], [0x1020, 14], [0x1021, 14], [0x1029, 4],
  [0x1101, 8], [0x1102, 25], [0x1103, 22], [0x1104, 22], [0x1105, 11], [0x1106, 10],
  [0x1108, 8], [0x1109, 8], [0x110b, 12], [0x110c, 14], [0x110d, 14], [0x110e, 14],
  [0x110f, 39], [0x1110, 39], [0x1111, 14], [0x1112, 14], [0x1113, 14],
  [0x1114, 56], [0x1115, 56], [0x1116, 22], [0x1118, 41], [0x1119, 41],
  [0x111a, 12], [0x111b, 12], [0x111c, 14], [0x111d, 14], [0x1124, 4],
  [0x1125, 14], [0x1126, 14], [0x1127, 14], [0x1128, 14], [0x1129, 14],
  [0x1136, 20], [0x1137, 18], [0x1138, 8], [0x113c, 26], [0x113e, 10], [0x1146, 39], [0x1147, 39]
]);

const variableNameOffset = async (reader: LegacyCodeViewReader, type: number): Promise<number | null> => {
  if (type === 3) return skipLegacyCodeViewNumeric(reader, 6);
  if ([0x1002, 0x1107, 0x112d].includes(type)) return skipLegacyCodeViewNumeric(reader, 8);
  if (type === 0xc) return 7 + (await reader.view(6, 1)).getUint8(0);
  if ([0x1005, 0x110a].includes(type)) return 9 + (await reader.view(8, 1)).getUint8(0);
  if ([0x1014, 0x1117].includes(type)) return 10 + 2 * await reader.uint16(8);
  return null;
};

export const readLegacyCodeViewSymbolName = async (
  reader: LegacyCodeViewReader, type: number
): Promise<string | null> => {
  const offset = NAME_OFFSETS.get(type) ?? await variableNameOffset(reader, type);
  if (offset == null) return null;
  return type >= 0x1100 ? reader.utf8(offset) : (await reader.pascal(offset)).name;
};
