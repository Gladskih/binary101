const SUBSECTIONS = ["Modules", "Module types", "Publics", "Public symbols", "Symbols", "Aligned symbols",
  "Source lines", "Source modules", "Libraries", "Global symbols", "Global publics", "Global types",
  "MPC", "Segment map", "Segment names", "Precompiled types", "Precompiled type map",
  "16-bit offset map", "32-bit offset map", "File index", "Static symbols"];

export const legacyCodeViewSubsectionName = (type: number): string =>
  SUBSECTIONS[type - 0x120] ?? `Unknown subsection 0x${type.toString(16)}`;

// Microsoft cvinfo.h CV_SYMBOL_ENUM / LEAF_ENUM_e. These are record categories,
// not invented meanings for opaque data or vendor records.
const SYMBOL_NAMES = new Map<number, string>([
  [1, "Compiler"], [2, "Register variable"], [3, "Constant"], [4, "User-defined type"], [5, "Symbol search"],
  [6, "Scope end"], [7, "Reserved space"], [8, "Reserved"], [9, "Object file"], [10, "End of arguments"],
  [11, "COBOL type"], [12, "Register variable"], [13, "Return description"], [14, "This pointer"],
  [0x400, "Procedure reference"], [0x401, "Data reference"], [0x402, "Alignment"],
  [0x403, "Local procedure reference"], [0x404, "Vendor symbol"],
  [0x1012, "Frame metadata"], [0x1013, "Compiler"], [0x1029, "Namespace"],
  [0x1101, "Object file"], [0x1102, "Thunk"], [0x1103, "Block"], [0x1104, "With expression"],
  [0x1105, "Label"], [0x1106, "Register variable"], [0x1107, "Constant"], [0x1108, "User-defined type"],
  [0x1109, "COBOL type"], [0x110a, "Register variable"], [0x110b, "Stack variable"], [0x110c, "Local data"],
  [0x110d, "Global data"], [0x110e, "Public symbol"], [0x110f, "Local procedure"], [0x1110, "Global procedure"],
  [0x1111, "Register-relative variable"], [0x1112, "Local thread data"], [0x1113, "Global thread data"],
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

export const legacyCodeViewSymbolName = (type: number): string => {
  const classic = type >= 0x100 && type <= 0x10c ? CLASSIC_SYMBOLS[type - 0x100]
    : type >= 0x200 && type <= 0x20f ? CLASSIC_SYMBOLS[type - 0x200] : undefined;
  return SYMBOL_NAMES.get(type) ?? classic ?? WIDE_SYMBOLS[type - 0x1001] ?? `Symbol record 0x${type.toString(16)}`;
};

const TYPE_NAMES = new Map<number, string>([
  [1, "Modifier"], [2, "Pointer"], [3, "Array"], [4, "Class"], [5, "Structure"], [6, "Union"], [7, "Enum"],
  [8, "Procedure"], [9, "Member function"], [10, "Virtual table shape"], [0x200, "Skip"], [0x201, "Arguments"],
  [0x202, "Default argument"], [0x203, "List"], [0x204, "Fields"], [0x205, "Derived types"],
  [0x206, "Bitfield"], [0x207, "Methods"], [0x208, "Array dimensions"], [0x209, "Array dimensions"],
  [0x1001, "Modifier"], [0x1002, "Pointer"], [0x1003, "Array"], [0x1004, "Class"], [0x1005, "Structure"],
  [0x1006, "Union"], [0x1007, "Enum"], [0x1008, "Procedure"], [0x1009, "Member function"], [0x1010, "Alias"],
  [0x1201, "Arguments"], [0x1203, "Fields"], [0x1205, "Bitfield"], [0x1206, "Methods"],
  [0x1503, "Array"], [0x1504, "Class"], [0x1505, "Structure"], [0x1506, "Union"], [0x1507, "Enum"],
  [0x150a, "Alias"], [0x1519, "Interface"],
  [0x11, "Dimensioned array"], [0x100c, "Dimensioned array"], [0x1508, "Dimensioned array"],
  [0x13, "Precompiled type file"], [0x100e, "Precompiled type file"], [0x1509, "Precompiled type file"],
  [0x16, "Type server PDB path"], [0x1501, "Type server PDB path"], [0x1515, "Type server PDB path"],
  [0x1202, "Default argument"], [0x150b, "Default argument"], [0x1516, "Strided array"],
  [0x151b, "Vector"], [0x151c, "Matrix"], [0x151d, "Virtual table"],
  [0x1601, "Function ID"], [0x1602, "Member function ID"], [0x1605, "String ID"]
]);

export const legacyCodeViewTypeName = (type: number): string => TYPE_NAMES.get(type) ??
  `Type record 0x${type.toString(16)}`;

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
