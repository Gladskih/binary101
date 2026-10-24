// CV_fldattr_t in Microsoft's published cvinfo.h.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const attributeFlags = (attributes: number): string[] => [
  attributes & 0x20 ? "compiler-generated declaration" : "", attributes & 0x40 ? "not inheritable" : "",
  attributes & 0x80 ? "not constructible" : "", attributes & 0x100 ? "compiler-generated definition" : "",
  attributes & 0x200 ? "sealed" : "",
  attributes & ~0x3ff ? `unknown attribute bits 0x${(attributes & ~0x3ff).toString(16)}` : ""
];

export const codeViewMemberAttributes = (attributes: number): string[] => [
  ["", "private", "protected", "public"][attributes & 3]!,
  ["", "virtual", "static", "friend", "introducing virtual", "pure virtual",
    "pure introducing virtual"][attributes >>> 2 & 7]
    ?? `unknown method property ${attributes >>> 2 & 7}`, ...attributeFlags(attributes)
].filter(Boolean);
