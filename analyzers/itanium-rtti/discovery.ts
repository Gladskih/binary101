import { readItaniumBases } from "./bases.js";
import { createItaniumRecords, isSupportedTypeName, type ItaniumRecords } from "./records.js";
import { findItaniumRuntime } from "./runtime.js";
import type {
  ItaniumClassKind, ItaniumRttiAnalysis, ItaniumRttiImage, ItaniumType
} from "./types.js";

const readSupportedName = async (records: ItaniumRecords, address: number): Promise<string | null> => {
  const name = await records.name(address);
  return name && isSupportedTypeName(name) ? name : null;
};

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
    if (!image.relocations.has(address)) return null;
    const kind = kinds.get(image.pointers.get(address)!);
    if (!kind) return null;
    const name = await readSupportedName(records, address);
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
    const result = { address, name, kind, ...body };
    cache.set(address, result);
    return result;
  };
  return { parse, cache };
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
  // Class discovery depends only on the validated runtime and the RTTI object itself.
  const typeAddresses = [...image.pointers].filter(([site, target]) =>
    image.relocations.has(site) && kinds.has(target)
  ).map(([site]) => site).sort((left, right) => image.readOrder(left) - image.readOrder(right));
  await records.prepareTypes(typeAddresses);
  for (const address of typeAddresses) await graph.parse(address);
  if (records.nameValidationIncomplete) {
    warnings.add("Itanium RTTI name validation budget exhausted; some types were omitted.");
  }
  const types = [...graph.cache.values()].filter(type => type != null)
    .sort((left, right) => left.address - right.address);
  return { types, warnings: [...warnings] };
};
