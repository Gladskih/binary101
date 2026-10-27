import type { EhImage, MsvcEhRecord } from "./types.js";

const readScope = (image: EhImage, entry: DataView | null) => {
  if (!entry) return null;
  const beginRva = entry.getUint32(0, true), endRva = entry.getUint32(4, true);
  const filterRva = entry.getUint32(8, true), targetRva = entry.getUint32(12, true);
  if (endRva <= beginRva || !image.code(beginRva, endRva - beginRva)) return null;
  const validFilter = targetRva === 0 ? image.code(filterRva) : filterRva === 1 || image.code(filterRva);
  const validTarget = targetRva === 0 || image.code(targetRva);
  return validFilter && validTarget ? { beginRva, endRva, filterRva, targetRva } : null;
};

export const parseSehScopes = async (
  image: EhImage, rva: number
): Promise<NonNullable<MsvcEhRecord["scopes"]> | null> => {
  // MSVC CRT src/vcruntime/riscchandler.cpp: SCOPE_TABLE, BeginAddress inclusive / EndAddress exclusive.
  // https://github.com/llvm/llvm-project/blob/main/llvm/lib/CodeGen/AsmPrinter/WinException.cpp
  const header = await image.read(rva, 4);
  if (!header) return null;
  const count = header.getUint32(0, true);
  if (!count || count > Math.floor(image.available(rva + 4) / 16)) return null;
  const scopes: NonNullable<MsvcEhRecord["scopes"]> = [];
  for (let index = 0; index < count; index++) {
    const scope = readScope(image, await image.read(rva + 4 + index * 16, 16));
    if (!scope) return null;
    scopes.push(scope);
  }
  return scopes;
};
