import type { PeImportParseResult } from "../imports/index.js";
import type { PeImportEntry } from "../imports/index.js";
import type { PeExportEntry } from "../directories/exports.js";
import type { EhFunctionSymbol, EhImage, MsvcEhPersonality } from "./types.js";
import { decodeEhThunk } from "./thunks.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../optional-header/magic.js";
import { IMAGE_THUNK_DATA32_SIZE, IMAGE_THUNK_DATA64_SIZE } from "../imports/thunk-layout.js";

export interface EhPersonality {
  // Canonical decoder ABI; evidence retains the actual import/export/symbol name.
  name: MsvcEhPersonality;
  evidence: string;
}

export const getEhPersonalityName = (name: string): MsvcEhPersonality | null => {
  if (name === "__CxxFrameHandler3" || name === "__CxxFrameHandler4" ||
      name === "__C_specific_handler" || name === "_except_handler3" || name === "_except_handler4") return name;
  // MSVC CRT src/x64/gshandlereh{,4}.cpp passes the same first FuncInfo RVA to FH3/FH4.
  if (name === "__GSHandlerCheck_EH") return "__CxxFrameHandler3";
  if (name === "__GSHandlerCheck_EH4") return "__CxxFrameHandler4";
  // MSVC 14.51 /GS /FAs (MsvcSeh.c) emits Count + SCOPE_RECORDs immediately
  // after this handler RVA, then GS data. The linked native test independently
  // validates scope ownership and EHCONT membership; the GS cookie is not decoded.
  // https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check
  // https://learn.microsoft.com/en-us/cpp/build/reference/fa-fa-listing-file
  if (name === "__GSHandlerCheck_SEH") return "__C_specific_handler";
  return null;
};

const addIdentity = (map: Map<number, EhPersonality | null>, rva: number, identity: EhPersonality): void => {
  const existing = map.get(rva);
  map.set(rva, map.has(rva) && existing?.name !== identity.name ? null : identity);
};

const addImportIdentities = (
  slots: Map<number, EhPersonality | null>, entry: PeImportEntry, stride: number
): void => {
  if (!entry.dll || entry.lookupSource !== "import-lookup-table" || !entry.thunkTableTerminated) return;
  for (const [index, fn] of entry.functions.entries()) {
    const name = getEhPersonalityName(fn.name ?? "");
    if (name) addIdentity(slots, entry.firstThunkRva + index * stride,
      { name, evidence: `${entry.dll}!${fn.name} via import lookup table` });
  }
};

const addExportIdentity = (
  image: EhImage, targets: Map<number, EhPersonality | null>, entry: PeExportEntry
): void => {
  const names = entry.names.map(getEhPersonalityName).filter(name => name != null);
  if (!entry.forwarder && names.length === 1 && image.code(entry.rva)) {
    addIdentity(targets, entry.rva, { name: names[0]!, evidence: `export ${entry.names.join(", ")}` });
  }
};

const addParsedImportIdentities = (
  slots: Map<number, EhPersonality | null>, imports: PeImportParseResult | null, stride: number
): void => {
  // The parser may recover a name after masking reserved thunk bits. Its warnings
  // therefore preclude identity here. IAT readability is checked independently below.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-lookup-table
  if (!imports || imports.warning || imports.thunkEntrySize !== stride) return;
  for (const entry of imports.entries) addImportIdentities(slots, entry, stride);
};

export const createEhPersonalityResolver = (
  image: EhImage, imports: PeImportParseResult | null, exports: PeExportEntry[],
  symbols: readonly EhFunctionSymbol[] = []
) => {
  const slots = new Map<number, EhPersonality | null>();
  const targets = new Map<number, EhPersonality | null>();
  const stride = image.core.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC
    ? IMAGE_THUNK_DATA64_SIZE : IMAGE_THUNK_DATA32_SIZE;
  addParsedImportIdentities(slots, imports, stride);
  for (const entry of exports) addExportIdentity(image, targets, entry);
  for (const symbol of symbols) {
    const name = getEhPersonalityName(symbol.name);
    if (name && image.code(symbol.rva)) addIdentity(targets, symbol.rva,
      { name, evidence: `${symbol.source} function symbol ${symbol.name}` });
  }
  return async (rva: number): Promise<EhPersonality | null> => {
    const visited = new Set<number>();
    let current = rva;
    while (!targets.has(current) && !visited.has(current)) {
      visited.add(current);
      const thunk = await decodeEhThunk(image, current);
      if (!thunk) break;
      if (thunk.kind === "branch") current = thunk.rva;
      else targets.set(current, await image.read(thunk.rva, stride) ? slots.get(thunk.rva) ?? null : null);
    }
    const result = targets.get(current) ?? null;
    for (const address of visited) targets.set(address, result);
    return result;
  };
};
