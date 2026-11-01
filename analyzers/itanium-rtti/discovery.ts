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
  kinds: Map<number, ItaniumClassKind>
) => {
  const cache = new Map<number, ItaniumType | null>();
  const parse = async (address: number): Promise<ItaniumType | null> => {
    if (cache.has(address)) return cache.get(address)!;
    // Cache the pending node as invalid so inheritance cycles cannot recurse forever.
    cache.set(address, null);
    if (!image.relocations.has(address)) return null;
    const kind = kinds.get(image.pointers.get(address)!);
    if (!kind) return null;
    const name = await readSupportedName(records, address);
    if (!name) return null;
    const body = await readItaniumBases(image, address, kind);
    if (!body) return null;
    for (const base of body.bases) {
      if (await parse(base.typeAddress)) continue;
      cache.set(address, null);
      return null;
    }
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
  const graph = createGraphParser(image, records, kinds);
  // ABI 2.9.2: typeid/exceptions can emit RTTI without any user vtable.
  // Class discovery depends only on the validated runtime and the RTTI object itself.
  const typeAddresses = [...image.pointers].filter(([site, target]) =>
    image.relocations.has(site) && kinds.has(target)
  ).map(([site]) => site).sort((left, right) => image.readOrder(left) - image.readOrder(right));
  await records.prepareTypes(typeAddresses);
  for (const address of typeAddresses) await graph.parse(address);
  const types = [...graph.cache.values()].filter(type => type != null)
    .sort((left, right) => left.address - right.address);
  return { types, warnings: [] };
};
