"use strict";

import type { PeClrMetadataIndex, PeClrTypeSignature } from "./types.js";

const genericArguments = (signature: PeClrTypeSignature | undefined): string[] => {
  if (signature?.issues?.length) return [];
  const match = signature?.type?.match(/^(?:class|valuetype) Type(?:Def|Ref)#\d+<(.*)>$/);
  if (!match) return [];
  // Split our validated signature text at top-level commas; nested generic arguments,
  // array shapes and function-pointer parameter lists can contain their own commas.
  const argumentsText = match[1]!;
  const argumentsList: string[] = [];
  let depth = 0;
  let start = 0;
  for (let offset = 0; offset < argumentsText.length; offset += 1) {
    const character = argumentsText[offset]!;
    if ("<[(".includes(character)) depth += 1;
    if ("])".includes(character) || (character === ">" && argumentsText[offset - 1] !== "-")) depth -= 1;
    if (character !== "," || depth !== 0) continue;
    argumentsList.push(argumentsText.slice(start, offset).trim());
    start = offset + 1;
  }
  argumentsList.push(argumentsText.slice(start).trim());
  return argumentsList;
};

export const resolveAttributeGenericParameters = (
  parameterTypes: Array<string | null>, owner: PeClrMetadataIndex | undefined,
  specifications: ReadonlyMap<number, PeClrTypeSignature> | undefined
): Array<string | null> => {
  // CustomAttributeDecoder substitutes VAR using the constructor's owning generic TypeSpec.
  // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Reflection.Metadata/src/System/Reflection/Metadata/Ecma335/CustomAttributeDecoder.cs
  if (!owner?.valid || owner.tableId !== 0x1b) return parameterTypes;
  const argumentsList = genericArguments(specifications?.get(owner.row));
  return parameterTypes.map(type => {
    const match = type?.match(/^var (\d+)(\[\])?$/);
    if (!match || !argumentsList[Number(match[1])]) return type;
    return `${argumentsList[Number(match[1])]}${match[2] ?? ""}`;
  });
};
