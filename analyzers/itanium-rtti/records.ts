import { createNames } from "./names.js";
import type { ItaniumRttiImage, ItaniumVtable } from "./types.js";

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

const hasRuntimeFunctions = (image: ItaniumRttiImage, address: number): boolean => {
  const first = image.pointers.get(address);
  const second = image.pointers.get(address + image.pointerSize);
  if (first == null || second == null) return false;
  return image.isExecutable(first) && image.isExecutable(second);
};

const hasFirstEntry = (image: ItaniumRttiImage, address: number, raw: bigint): boolean => {
  // ABI 3.2.4 permits null pure/deleted entries. This conservative PE subset accepts
  // only raw null or relocated code; it neither identifies a method nor bounds the table.
  // https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vcall
  if (!image.relocations.has(address)) return raw === 0n;
  const target = image.pointers.get(address);
  return raw !== 0n && target != null && image.isExecutable(target);
};

const readTable = async (image: ItaniumRttiImage, address: number): Promise<ItaniumVtable | null> => {
  const width = image.pointerSize;
  if (address < 2 * width || address % width !== 0) return null;
  const typeAddress = image.pointers.get(address - width);
  if (typeAddress == null || !image.relocations.has(address - width)) return null;
  if (image.relocations.has(address - 2 * width)) return null;
  // ABI 2.5.2: offset-to-top, typeinfo pointer, then the address point.
  const header = await image.read(address - 2 * width, 3 * width);
  if (header.byteLength !== 3 * width || readSignedWord(header, 0, width) !== 0n) return null;
  if (!hasFirstEntry(image, address, readSignedWord(header, 2 * width, width))) return null;
  return { address, typeAddress, offsetToTop: 0 };
};

const createPreparation = (
  image: ItaniumRttiImage, names: ReturnType<typeof createNames>,
  table: (address: number) => Promise<ItaniumVtable | null>
) => {
  let prepared: number[] | null = null;
  return async (): Promise<number[]> => {
    if (prepared) return prepared;
    const candidates = [...image.pointers].filter(([, target]) =>
      image.pointers.has(target + image.pointerSize)
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
  const tables = new Map<number, Promise<ItaniumVtable | null>>();
  const runtimeTables = new Map<number, Promise<ItaniumVtable | null>>();
  const table = (address: number): Promise<ItaniumVtable | null> => {
    if (!tables.has(address)) tables.set(address, readTable(image, address));
    return tables.get(address)!;
  };
  const runtimeTable = async (address: number): Promise<ItaniumVtable | null> => {
    // Bootstrap still requires two code pointers; ordinary tables only check their first entry.
    if (!hasRuntimeFunctions(image, address)) return null;
    if ((await image.read(address, 2 * image.pointerSize)).byteLength !== 2 * image.pointerSize) {
      return null;
    }
    return table(address);
  };
  return {
    prepare: createPreparation(image, names, table),
    prepareTypes: names.prepare,
    name: names.name,
    structuralName: names.structuralName,
    get nameValidationIncomplete(): boolean { return names.exhausted; },
    table,
    runtimeTable: (address: number): Promise<ItaniumVtable | null> => {
      if (!runtimeTables.has(address)) runtimeTables.set(address, runtimeTable(address));
      return runtimeTables.get(address)!;
    }
  };
};

export type ItaniumRecords = ReturnType<typeof createItaniumRecords>;
