import { readItaniumBases } from "./bases.js";
import { createItaniumRecords, readSignedWord, type ItaniumRecords } from "./records.js";
import { findItaniumRuntime } from "./runtime.js";
import type {
  ItaniumClassKind, ItaniumRttiAnalysis, ItaniumRttiImage, ItaniumType, ItaniumVtable
} from "./types.js";

const createGraphParser = (
  image: ItaniumRttiImage, records: ItaniumRecords,
  kinds: Map<number, ItaniumClassKind>, warnings: Set<string>
) => {
  const cache = new Map<number, ItaniumType | null>();
  const active = new Set<number>();
  const parse = async (address: number): Promise<ItaniumType | null> => {
    if (cache.has(address)) return cache.get(address)!;
    // Resource policy: bound recursion independently of the size of hostile input.
    if (active.size >= 64) {
      warnings.add("Itanium RTTI inheritance depth limit reached; some types were omitted.");
      return null;
    }
    cache.set(address, null);
    const kind = kinds.get(image.pointers.get(address)!);
    if (!kind) return null;
    const name = await records.name(address);
    if (!name) return null;
    const body = await readItaniumBases(image, address, kind);
    if (!body) return null;
    active.add(address);
    for (const base of body.bases) {
      if (await parse(base.typeAddress)) continue;
      active.delete(address);
      cache.set(address, null);
      return null;
    }
    active.delete(address);
    const result = { address, name, kind, ...body };
    cache.set(address, result);
    return result;
  };
  return { parse, cache };
};

const reachableTypes = (
  roots: number[], cache: Map<number, ItaniumType | null>
): ItaniumType[] => {
  const types = new Map<number, ItaniumType>();
  const pending = [...roots];
  while (pending.length) {
    const address = pending.pop()!;
    if (types.has(address)) continue;
    const type = cache.get(address)!;
    types.set(address, type);
    pending.push(...type.bases.map(base => base.typeAddress));
  }
  return [...types.values()];
};

const hasVirtualBaseSlots = async (
  image: ItaniumRttiImage, address: number, type: ItaniumType
): Promise<boolean> => {
  for (const base of type.bases) {
    if (!base.isVirtual) continue;
    // ABI 2.9.5: virtual offsets locate vbase entries preceding the address point.
    const slot = address + base.offset;
    if (!Number.isSafeInteger(slot) || slot < 0 || image.relocations.has(slot)) return false;
    const view = await image.read(slot, image.pointerSize);
    if (view.byteLength !== image.pointerSize) return false;
    if (readSignedWord(view, 0, image.pointerSize) < 0n) return false;
  }
  return true;
};

const omitRttiOverlaps = (
  tables: ItaniumVtable[], types: ItaniumType[], width: number
): ItaniumVtable[] => {
  // ABI 2.9.5: fixed class/SI records and a counted trailing VMI base array.
  // Reject overlap of either header or first slot with already validated metadata.
  const ranges = types.map(type => ({ start: type.address, end: type.address +
    (type.kind === "class" ? 2 * width : type.kind === "si" ? 3 * width :
      2 * width + 8 + type.bases.length * 2 * width)
  })).sort((left, right) => left.start - right.start);
  const rejected = new Set<number>();
  let index = 0;
  // Two ordered passes avoid comparing every vtable against every RTTI object.
  for (const table of [...tables].sort((left, right) => left.address - right.address)) {
    while (index < ranges.length && ranges[index]!.end <= table.address - 2 * width) index++;
    if (index < ranges.length && ranges[index]!.start < table.address + width) {
      rejected.add(table.address);
    }
  }
  return tables.filter(table => !rejected.has(table.address));
};

export const discoverItaniumRtti = async (
  image: ItaniumRttiImage
): Promise<ItaniumRttiAnalysis | null> => {
  const records = createItaniumRecords(image);
  const kinds = await findItaniumRuntime(image, records);
  if (!kinds.size) return null;
  const warnings = new Set<string>();
  const graph = createGraphParser(image, records, kinds, warnings);
  const vtables: ItaniumRttiAnalysis["vtables"] = [];
  for (const address of await records.prepare()) {
    const table = await records.table(address);
    if (!table) continue;
    const type = await graph.parse(table.typeAddress);
    if (type && await hasVirtualBaseSlots(image, address, type)) vtables.push(table);
  }
  // Wait until the whole graph is parsed: an enclosing RTTI object may be encountered later.
  const confirmed = omitRttiOverlaps(vtables,
    [...graph.cache.values()].filter(type => type != null), image.pointerSize);
  const types = reachableTypes(confirmed.map(table => table.typeAddress), graph.cache);
  return confirmed.length ? { types, vtables: confirmed, warnings: [...warnings] } : null;
};
