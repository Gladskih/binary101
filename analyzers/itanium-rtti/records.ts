import { createNames } from "./names.js";
import type { ItaniumRttiImage } from "./types.js";

// Itanium ABI 2.9.5, 5.1.2: https://itanium-cxx-abi.github.io/cxx-abi/abi.html
// Deliberately accept only source names and their simple nested/std forms.
const sourceNameEnd = (rest: string): number | null => {
  const match = /^[1-9][0-9]*/.exec(rest);
  if (!match) return null;
  const end = match[0].length + Number(match[0]);
  return end <= rest.length && /^[A-Za-z_][A-Za-z_0-9]*$/.test(rest.slice(match[0].length, end))
    ? end : null;
};

export const isSupportedTypeName = (name: string): boolean => {
  const nested = name.startsWith("N") && name.endsWith("E");
  const body = nested ? name.slice(1, -1) : name;
  let rest = body.startsWith("St") ? body.slice(2) : body;
  let count = 0;
  while (rest.length) {
    const end = sourceNameEnd(rest);
    if (end == null) return false;
    rest = rest.slice(end);
    count++;
  }
  return count > 0 && (nested || count === 1);
};

export const readSignedWord = (view: DataView, offset: number, width: 4 | 8): bigint =>
  width === 8 ? view.getBigInt64(offset, true) : BigInt(view.getInt32(offset, true));

// Only a bootstrap candidate; never published as a user vtable or method source.
export interface ItaniumRuntimeVtable { typeAddress: number }

const hasRuntimeFunctions = (image: ItaniumRttiImage, address: number): boolean =>
  [address, address + image.pointerSize].every(site => {
    const target = image.pointers.get(site);
    return image.relocations.has(site) && target != null && image.isExecutable(target);
  });

const isRuntimeHeader = (view: DataView, width: 4 | 8): boolean =>
  view.byteLength === 4 * width && readSignedWord(view, 0, width) === 0n &&
  [2 * width, 3 * width].every(offset => readSignedWord(view, offset, width) !== 0n);

const readRuntimeTable = async (
  image: ItaniumRttiImage, address: number
): Promise<ItaniumRuntimeVtable | null> => {
  const width = image.pointerSize;
  if (address < 2 * width || address % width !== 0) return null;
  if (!hasRuntimeFunctions(image, address)) return null;
  const typeAddress = image.pointers.get(address - width);
  if (typeAddress == null || !image.relocations.has(address - width)) return null;
  if (image.relocations.has(address - 2 * width)) return null;
  // ABI 2.5.2: offset-to-top and typeinfo precede the address point.
  // Runtime bootstrap deliberately requires two relocated executable pointers.
  return isRuntimeHeader(await image.read(address - 2 * width, 4 * width), width)
    ? { typeAddress } : null;
};

const createPreparation = (
  image: ItaniumRttiImage, names: ReturnType<typeof createNames>,
  table: (address: number) => Promise<ItaniumRuntimeVtable | null>
) => {
  let prepared: number[] | null = null;
  return async (): Promise<number[]> => {
    if (prepared) return prepared;
    const candidates = [...image.pointers].filter(([site, target]) =>
      image.pointers.has(target + image.pointerSize) && hasRuntimeFunctions(image, site + image.pointerSize)
    ).map(([site]) => site + image.pointerSize)
      .sort((left, right) => image.readOrder(left) - image.readOrder(right));
    const typeAddresses = new Set<number>();
    for (const address of candidates) {
      const entry = await table(address);
      if (entry) typeAddresses.add(entry.typeAddress);
    }
    await names.prepare(typeAddresses);
    prepared = candidates;
    return prepared;
  };
};

export const createItaniumRecords = (image: ItaniumRttiImage) => {
  const names = createNames(image);
  const tables = new Map<number, Promise<ItaniumRuntimeVtable | null>>();
  const runtimeTable = (address: number): Promise<ItaniumRuntimeVtable | null> => {
    if (!tables.has(address)) tables.set(address, readRuntimeTable(image, address));
    return tables.get(address)!;
  };
  return {
    prepareRuntime: createPreparation(image, names, runtimeTable),
    prepareTypes: names.prepare,
    name: names.name,
    get nameValidationIncomplete(): boolean { return names.exhausted; },
    runtimeTable
  };
};

export type ItaniumRecords = ReturnType<typeof createItaniumRecords>;
