import { hllSymbolName, hllTypeName } from "./hll-kinds.js";

const SUBSECTIONS = ["Modules", "Module types", "Publics", "Public symbols", "Symbols", "Aligned symbols",
  "Source lines", "Source modules", "Libraries", "Global symbols", "Global publics", "Global types",
  "MPC", "Segment map", "Segment names", "Precompiled types", "Precompiled type map",
  "16-bit offset map", "32-bit offset map", "File index", "Static symbols"];

const C6_SUBSECTIONS = new Map([[0x101, "Modules (C6)"], [0x102, "Public symbols (C6)"],
  [0x103, "Module types (C6)"], [0x104, "Symbols (C6)"], [0x105, "Source lines (C6)"],
  [0x106, "Libraries (C6)"], [0x108, "Compacted types (C6)"], [0x109, "Source lines with segments (C6)"]]);

export const legacyCodeViewSubsectionName = (type: number, signature?: string): string => {
  if (signature === "NB00") return C6_SUBSECTIONS.get(type)?.replace(" (C6)", " (CV3)")
    ?? `Unknown subsection 0x${type.toString(16)}`;
  if (signature === "NB04") return type === 0x10b ? "HLL source mappings"
    : C6_SUBSECTIONS.get(type)?.replace(" (C6)", "") ?? `Unknown subsection 0x${type.toString(16)}`;
  return SUBSECTIONS[type - 0x120] ?? C6_SUBSECTIONS.get(type) ?? `Unknown subsection 0x${type.toString(16)}`;
};

// Microsoft C Developer's Toolkit, 1.3/1.4; dumpsym6.cpp/debsym.h/typeinfo.h.
// https://www.pcjs.org/documents/books/mspl13/c/ctoolkit/
const C6_SYMBOLS = new Map([[0, "Block"], [1, "Procedure"], [2, "Scope end"], [4, "Stack variable"],
  [5, "Local data"], [11, "Label"], [12, "With expression"], [13, "Register variable"], [14, "Constant"],
  [15, "FORTRAN entry"], [16, "Padding"], [17, "Default segment"], [18, "COBOL typedef"], [22, "Execution model"]]);
const C6_TYPES = new Map([[92, "Bitfield"], [93, "Type alias"], [96, "String"], [103, "File"],
  [106, "Set"], [113, "Constant"], [114, "Code label"], [117, "Procedure"], [118, "Parameter"],
  [120, "Array"], [121, "Structure"], [122, "Pointer"], [123, "Scalar"], [126, "Real"],
  [127, "Type or member list"], [128, "Empty type"], [140, "Basic array"], [141, "FORTRAN string"],
  [142, "FORTRAN array bounds"], [144, "Skipped type indices"], [145, "Based pointer"],
  [166, "COBOL type reference"], [167, "COBOL type"]]);

// Microsoft cvinfo.h CV_SYMBOL_ENUM / LEAF_ENUM_e. These are record categories,
// not invented meanings for opaque data or vendor records.
const SYMBOL_NAMES = new Map<number, string>([
  [1, "Compiler"], [2, "Register variable"], [3, "Constant"], [4, "User-defined type"], [5, "Symbol search"],
  [6, "Scope end"], [7, "Reserved space"], [8, "Reserved"], [9, "Object file"], [10, "End of arguments"],
  [11, "COBOL type"], [12, "Register variable"], [13, "Return description"], [14, "This pointer"],
  [0x400, "Procedure reference"], [0x401, "Data reference"], [0x402, "Alignment"],
  [0x403, "Local procedure reference"], [0x404, "Vendor symbol"],
  [0x113b, "Discarded symbols"],
  [0x1012, "Frame metadata"], [0x1013, "Compiler"], [0x1029, "Namespace"],
  [0x1101, "Object file"], [0x1102, "Thunk"], [0x1103, "Block"], [0x1104, "With expression"],
  [0x1105, "Label"], [0x1106, "Register variable"], [0x1107, "Constant"], [0x1108, "User-defined type"],
  [0x1109, "COBOL type"], [0x110a, "Register variable"], [0x110b, "Stack variable"], [0x110c, "Local data"],
  [0x110d, "Global data"], [0x110e, "Public symbol"], [0x110f, "Local procedure"], [0x1110, "Global procedure"],
  [0x1111, "Register-relative variable"], [0x1112, "Local thread data"], [0x1113, "Global thread data"],
  [0x1019, "Annotations"], [0x113d, "Environment"], [0x1161, "PDB mapping"],
  [0x101a, "Global managed procedure"], [0x101b, "Local managed procedure"],
  [0x1022, "Managed frame-relative variable"], [0x1023, "Managed register variable"],
  [0x1024, "Managed slot variable"], [0x1025, "Managed multi-register variable"],
  [0x1026, "Managed register-relative variable"], [0x1027, "Managed multi-register variable"],
  [0x111e, "Managed frame-relative variable"], [0x111f, "Managed register variable"],
  [0x1120, "Managed slot variable"], [0x1121, "Managed multi-register variable"],
  [0x1122, "Managed register-relative variable"], [0x1123, "Managed multi-register variable"],
  [0x112a, "Global managed procedure"], [0x112b, "Local managed procedure"],
  [0x112e, "Attributed frame-relative variable"], [0x112f, "Attributed register variable"],
  [0x1130, "Attributed register-relative variable"], [0x1131, "Attributed multi-register variable"],
  [0x1148, "Local MIPS procedure"], [0x1149, "Global MIPS procedure"],
  [0x114a, "Local IA64 procedure"], [0x114b, "Global IA64 procedure"],
  [0x1151, "Global HLSL data"], [0x1152, "Local HLSL data"], [0x1153, "File-static variable"],
  [0x1154, "Group-shared local variable"], [0x1155, "Local DPC procedure"], [0x1156, "Local DPC procedure"],
  [0x1160, "Mini-PDB symbol reference"], [0x1162, "Global HLSL data"], [0x1163, "Local HLSL data"],
  [0x1164, "Global HLSL data"], [0x1165, "Local HLSL data"], [0x1169, "Hot-patch function"],
  [0x1171, "Indirect register-relative variable"],
  [0x1116, "Compiler"], [0x1124, "Namespace"], [0x1125, "Procedure reference"], [0x1126, "Data reference"],
  [0x1127, "Local procedure reference"], [0x1136, "Section"], [0x1137, "Section group"], [0x1138, "Export"],
  [0x113c, "Compiler"], [0x113e, "Local variable"], [0x1146, "Local procedure"], [0x1147, "Global procedure"]
]);
const CLASSIC_SYMBOLS = ["Stack variable", "Local data", "Global data", "Public symbol", "Local procedure",
  "Global procedure", "Thunk", "Block", "With expression", "Label", "Execution model", "Virtual table",
  "Register-relative variable", "Local thread data", "Global thread data", "Static link"];
const WIDE_SYMBOLS = ["Register variable", "Constant", "User-defined type", "COBOL type", "Register variable",
  "Stack variable", "Local data", "Global data", "Public symbol", "Local procedure", "Global procedure",
  "Virtual table", "Register-relative variable", "Local thread data", "Global thread data"];

const c6SymbolName = (type: number): string => {
  const name = C6_SYMBOLS.get(type & 0x7f);
  if (!name) return `C6 symbol record 0x${type.toString(16)}`;
  return [0, 1, 4, 5, 11, 12, 15].includes(type & 0x7f)
    ? `${name} (${type & 0x80 ? 32 : 16}-bit offsets)` : name;
};

const c7SymbolName = (type: number): string => {
  const classic = type >= 0x100 && type <= 0x10c ? CLASSIC_SYMBOLS[type - 0x100]
    : type >= 0x200 && type <= 0x20f ? CLASSIC_SYMBOLS[type - 0x200] : undefined;
  return SYMBOL_NAMES.get(type) ?? classic ?? WIDE_SYMBOLS[type - 0x1001] ?? `Symbol record 0x${type.toString(16)}`;
};

export const legacyCodeViewSymbolName = (type: number, encoding?: "c6" | "hll"): string => {
  if (encoding === "hll") return hllSymbolName(type);
  return encoding === "c6" ? c6SymbolName(type) : c7SymbolName(type);
};

// CV_VTS_desc_e in Microsoft's cvinfo.h.
export const legacyCodeViewVtableSlotName = (kind: number): string =>
  ["near", "far", "thin", "outer", "meta", "near32", "far32", "unused"][kind] ?? `unknown kind ${kind}`;

const TYPE_NAMES = new Map<number, string>([
  [1, "Modifier"], [2, "Pointer"], [3, "Array"], [4, "Class"], [5, "Structure"], [6, "Union"], [7, "Enum"],
  [8, "Procedure"], [9, "Member function"], [10, "Virtual table shape"], [0x200, "Skip"], [0x201, "Arguments"],
  [0x202, "Default argument"], [0x203, "List"], [0x204, "Fields"], [0x205, "Derived types"],
  [0x20c, "Referenced symbol"],
  [0x206, "Bitfield"], [0x207, "Methods"], [0x208, "Array dimensions"], [0x209, "Array dimensions"],
  [0x20a, "Variable array dimensions"], [0x20b, "Variable array dimensions"],
  [0x1207, "Array dimensions"], [0x1208, "Array dimensions"],
  [0x1209, "Variable array dimensions"], [0x120a, "Variable array dimensions"],
  [0x1001, "Modifier"], [0x1002, "Pointer"], [0x1003, "Array"], [0x1004, "Class"], [0x1005, "Structure"],
  [0x1006, "Union"], [0x1007, "Enum"], [0x1008, "Procedure"], [0x1009, "Member function"], [0x1010, "Alias"],
  [0x1200, "Skip"], [0x1201, "Arguments"], [0x1203, "Fields"], [0x1205, "Bitfield"], [0x1206, "Methods"],
  [0x1503, "Array"], [0x1504, "Class"], [0x1505, "Structure"], [0x1506, "Union"], [0x1507, "Enum"],
  [0x150a, "Alias"], [0x1519, "Interface"],
  // LLVM 007ca8ec1bd348000e42ada637c421cf5d28c11a CodeViewTypes.def.
  [0x1608, "Class (extended)"], [0x1609, "Structure (extended)"],
  [0x160a, "Union (extended)"], [0x160b, "Interface (extended)"],
  [0x11, "Dimensioned array"], [0x100c, "Dimensioned array"], [0x1508, "Dimensioned array"],
  [0x13, "Precompiled type file"], [0x100e, "Precompiled type file"], [0x1509, "Precompiled type file"],
  [0x14, "Precompiled type boundary"],
  [0x12, "Virtual table path"], [0x100d, "Virtual table path"],
  [0x16, "Type server PDB path"], [0x1501, "Type server PDB path"], [0x1515, "Type server PDB path"],
  [0x1202, "Default argument"], [0x150b, "Default argument"], [0x1516, "Strided array"],
  [0x151b, "Vector"], [0x151c, "Matrix"], [0x151d, "Virtual table"],
  [0x1601, "Function ID"], [0x1602, "Member function ID"], [0x1605, "String ID"],
  [0x1204, "Derived types"], [0x1603, "Build information"], [0x1604, "Substring list"],
  [0x1606, "Type source line"], [0x1607, "Type module source line"]
]);

export const legacyCodeViewTypeName = (type: number, encoding?: "c6" | "hll"): string => encoding === "hll"
  ? hllTypeName(type) : encoding === "c6"
  ? C6_TYPES.get(type) ?? `C6 type record 0x${type.toString(16)}`
  : TYPE_NAMES.get(type) ?? `Type record 0x${type.toString(16)}`;

// Field-list categories use separate leaf tags for 16-bit indices, ST and SZ names.
const FIELD_NAMES = new Map<number, string>([
  [0x400, "Base class"], [0x401, "Virtual base class"], [0x402, "Indirect virtual base class"],
  [0x403, "Enumerator"], [0x404, "Friend function"], [0x405, "Field list continuation"],
  [0x406, "Data member"], [0x407, "Static data member"], [0x408, "Overloaded method"],
  [0x409, "Nested type"], [0x40a, "Virtual table pointer"], [0x40b, "Friend class"],
  [0x40c, "Method"], [0x40d, "Virtual table offset"],
  [0x1400, "Base class"], [0x1401, "Virtual base class"], [0x1402, "Indirect virtual base class"],
  [0x1403, "Friend function"], [0x1404, "Field list continuation"], [0x1405, "Data member"],
  [0x1406, "Static data member"], [0x1407, "Overloaded method"], [0x1408, "Nested type"],
  [0x1409, "Virtual table pointer"], [0x140a, "Friend class"], [0x140b, "Method"],
  [0x140c, "Virtual table offset"], [0x140d, "Nested type"], [0x140e, "Member modification"], [0x140f, "Managed type"],
  [0x1502, "Enumerator"], [0x150c, "Friend function"], [0x150d, "Data member"],
  [0x150e, "Static data member"], [0x150f, "Overloaded method"], [0x1510, "Nested type"],
  [0x1511, "Method"], [0x1512, "Nested type"], [0x1513, "Member modification"],
  [0x1514, "Managed type"], [0x151a, "Base interface"]
]);

export const legacyCodeViewFieldName = (type: number): string => FIELD_NAMES.get(type) ??
  `Field record 0x${type.toString(16)}`;
