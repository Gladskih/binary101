// IBM HLL Symbol Scope Table and Complex Types Values.
// https://www.os2site.com/sw/dev/openwatcom/docs/ibmhll.htm
const SYMBOLS = new Map([[0, "Block"], [1, "Procedure"], [2, "Scope end"], [4, "Stack variable"],
  [5, "Static variable"], [6, "Thread-local variable"], [11, "Code label"], [12, "With expression"],
  [13, "Register variable"], [14, "Constant"], [15, "Secondary entry"], [16, "Padding"],
  [17, "Default segment"], [18, "Typedef"], [19, "Public symbol"], [20, "Member"], [21, "Based variable"],
  [22, "Tag"], [23, "Table"], [24, "External name mapping"], [25, "Extended tag"], [26, "Member function"],
  [27, "Scoped stack variable"], [28, "Scoped static variable"], [29, "Extended procedure"],
  [30, "Extended static variable"], [32, "Register-relative variable"], [33, "Based member"],
  [34, "Array symbol"], [64, "Compilation unit"], [65, "Reserved compiler function list"]]);
const TYPES = new Map([[0x40, "Class"], [0x41, "Base class"], [0x42, "Friend"], [0x43, "Class definition"],
  [0x45, "Member function"], [0x46, "Class member"], [0x48, "Reference"], [0x49, "Member pointer"],
  [0x51, "Scalar"], [0x52, "Set"], [0x53, "Entry"], [0x54, "Function"], [0x55, "Area"],
  [0x56, "Logical"], [0x57, "Stack"], [0x59, "Macro"], [0x5c, "Bit string"], [0x5d, "Type alias"],
  [0x60, "Character string"], [0x61, "Picture string"], [0x62, "Graphic string"], [0x65, "Format label"],
  [0x67, "File"], [0x6f, "Subrange"], [0x72, "Code label"], [0x75, "Procedure"], [0x78, "Array"],
  [0x79, "Structure or union"], [0x7a, "Pointer"], [0x7b, "Enum"], [0x7f, "Type or member list"]]);

export const hllSymbolName = (type: number): string => SYMBOLS.get(type) ?? `HLL symbol record 0x${type.toString(16)}`;
export const hllTypeName = (type: number): string => TYPES.get(type) ?? `HLL type record 0x${type.toString(16)}`;
