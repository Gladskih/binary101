import { readItaniumBases } from "./bases.js";
import { createItaniumRecords, isSupportedTypeName, readSignedWord, type ItaniumRecords } from "./records.js";
import { findItaniumRuntime } from "./runtime.js";
import type {
  ItaniumClassKind, ItaniumRttiAnalysis, ItaniumRttiImage, ItaniumType, ItaniumVtable
} from "./types.js";

type StructuralType = Omit<ItaniumType, "name"> & { name: string | null };

const hasSupportedHierarchy = (
  type: StructuralType, publishable: Map<number, ItaniumType>
): type is ItaniumType => type.name != null && isSupportedTypeName(type.name) &&
  type.bases.every(base => publishable.has(base.typeAddress));

const createGraphParser = (
  image: ItaniumRttiImage, records: ItaniumRecords,
  kinds: Map<number, ItaniumClassKind>, warnings: Set<string>
) => {
  const cache = new Map<number, StructuralType | null>();
  const publishable = new Map<number, ItaniumType>();
  const active = new Set<number>();
  const parse = async (address: number): Promise<StructuralType | null> => {
    if (cache.has(address)) return cache.get(address)!;
    // Resource policy: bound recursion independently of the size of hostile input.
    if (active.size >= 64) {
      warnings.add("Itanium RTTI inheritance depth limit reached; vtables omitted.");
      return null;
    }
    cache.set(address, null);
    const kind = kinds.get(image.pointers.get(address)!);
    if (!kind) return null;
    const name = await records.structuralName(address);
    if (!name) return null;
    const body = await readItaniumBases(image, address, kind, warnings);
    if (!body) return null;
    active.add(address);
    for (const base of body.bases) {
      if (await parse(base.typeAddress)) continue;
      active.delete(address);
      cache.set(address, null);
      return null;
    }
    active.delete(address);
    const result = { address, name: name.value, kind, ...body };
    cache.set(address, result);
    // Unknown name syntax never invalidates structural metadata, including its bases.
    // Preserve publication of supported hierarchies only, with no dangling base references.
    if (hasSupportedHierarchy(result, publishable)) publishable.set(address, result);
    return result;
  };
  return { parse, cache, publishable };
};

const reachableTypes = (
  roots: number[], cache: Map<number, ItaniumType>
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
  image: ItaniumRttiImage, address: number, type: StructuralType
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
  tables: ItaniumVtable[], types: StructuralType[], width: number
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
  for (const table of tables) {
    while (index < ranges.length && ranges[index]!.end <= table.address - 2 * width) index++;
    if (index < ranges.length && ranges[index]!.start < table.address + width) {
      rejected.add(table.address);
    }
  }
  return tables.filter(table => !rejected.has(table.address));
};

const omitAmbiguousVtables = (tables: ItaniumVtable[], width: number): ItaniumVtable[] =>
  // Conservative ordinary-vtable policy, not an ABI prohibition on interleaving.
  // https://clang.llvm.org/docs/ControlFlowIntegrityDesign.html#interleave-virtual-tables
  // Sorted minimum ranges [address - 2*width, address + width) must not overlap.
  // Compare original neighbors so every member of an overlapping chain is omitted.
  tables.filter((table, index) => {
    const previous = tables[index - 1];
    const next = tables[index + 1];
    return (!previous || table.address - previous.address >= 3 * width) &&
      (!next || next.address - table.address >= 3 * width);
  });

const readVtables = async (
  image: ItaniumRttiImage, records: ItaniumRecords, graph: ReturnType<typeof createGraphParser>
): Promise<ItaniumVtable[]> => {
  const vtables: ItaniumVtable[] = [];
  for (const address of await records.prepare()) {
    const table = await records.table(address);
    if (!table) continue;
    const type = await graph.parse(table.typeAddress);
    if (!type) continue;
    if (await hasVirtualBaseSlots(image, address, type)) vtables.push(table);
  }
  return vtables;
};

export const discoverItaniumRtti = async (
  image: ItaniumRttiImage
): Promise<ItaniumRttiAnalysis | null> => {
  const records = createItaniumRecords(image);
  const kinds = await findItaniumRuntime(image, records);
  if (!kinds.size) return null;
  const warnings = new Set<string>();
  const graph = createGraphParser(image, records, kinds, warnings);
  // ABI 2.9.2: typeid/exceptions can emit RTTI without any user vtable.
  // Validate every relocated runtime vptr before using RTTI ranges to exclude overlaps.
  const typeAddresses = [...image.pointers].filter(([site, target]) =>
    image.relocations.has(site) && kinds.has(target)
  ).map(([site]) => site).sort((left, right) => image.readOrder(left) - image.readOrder(right));
  await records.prepareTypes(typeAddresses);
  for (const address of typeAddresses) await graph.parse(address);
  const vtables = await readVtables(image, records, graph);
  if (records.nameValidationIncomplete) {
    warnings.add("Itanium RTTI name validation budget exhausted; vtables omitted.");
  }
  if (warnings.size) return { types: [], vtables: [], warnings: [...warnings] };
  // Wait until the whole graph is parsed: an enclosing RTTI object may be encountered later.
  // Sort once for both overlap passes; physical read order is unaffected.
  vtables.sort((left, right) => left.address - right.address);
  const confirmed = omitAmbiguousVtables(omitRttiOverlaps(vtables,
    [...graph.cache.values()].filter(type => type != null), image.pointerSize), image.pointerSize)
    .filter(table => graph.publishable.has(table.typeAddress));
  const types = reachableTypes(confirmed.map(table => table.typeAddress), graph.publishable);
  return confirmed.length ? { types, vtables: confirmed, warnings: [...warnings] } : null;
};
