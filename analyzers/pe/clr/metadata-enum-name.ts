"use strict";

import type { ClrAssemblyIdentity } from "./metadata-assembly-identity.js";
import { parseClrAssemblyName } from "./metadata-assembly-name.js";

export interface ClrSerializedEnumName {
  typeName: string;
  assembly: Partial<ClrAssemblyIdentity> | null;
}

// Enum serialization uses reflection names, not arrays/pointers or generic instantiations.
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Reflection.Metadata/src/System/Reflection/Metadata/TypeNameParserHelpers.cs
const finishTypeName = (end: number, segmentStart: number): number | null => end === segmentStart ? null : end;
const typeNameEnd = (name: string): number | null => {
  let segmentStart = 0;
  for (let index = 0; index < name.length; index++) {
    const character = name[index]!;
    if (character === ",") return finishTypeName(index, segmentStart);
    if ("[]*&\0".includes(character)) return null;
    if (character === "\\") {
      if (++index === name.length || !"[]*&+,\\".includes(name[index]!)) return null;
    } else if (character === "+") {
      if (index === segmentStart) return null;
      segmentStart = index + 1;
    }
  }
  return finishTypeName(name.length, segmentStart);
};

export const parseSerializedEnumName = (name: string): ClrSerializedEnumName | null => {
  // Runtime TrimStart uses Char.IsWhiteSpace (Unicode White_Space), unlike JavaScript trimStart.
  // https://learn.microsoft.com/en-us/dotnet/api/system.char.iswhitespace
  const text = name.replace(/^\p{White_Space}+/u, "");
  const end = typeNameEnd(text);
  if (end == null) return null;
  if (end === text.length) return { typeName: text, assembly: null };
  const assembly = parseClrAssemblyName(text.slice(end + 1));
  return assembly ? { typeName: text.slice(0, end), assembly } : null;
};
