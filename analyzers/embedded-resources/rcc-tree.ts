import type { FileRangeReader } from "../file-range-reader.js";
import type { RccNode, ResourceRange, StoredResourceContent } from "./types.js";
import { readResource, requireResource } from "./reader.js";
import { readRccName } from "./rcc-names.js";
import { resourceZstdSize } from "./zstd-frame.js";

// All RCC integers are big endian; nodes are 14 bytes (v1) or 22 bytes (v2/v3).
// https://code.qt.io/cgit/qt/qtbase.git/tree/src/corelib/io/qresource.cpp
// https://code.qt.io/cgit/qt/qtbase.git/tree/src/tools/rcc/rcc.cpp (writeDataInfo)
const readPayload = async (reader: FileRangeReader, data: ResourceRange,
  offset: number, flags: number): Promise<StoredResourceContent> => {
  const size = (await readResource(reader, data, offset, 4)).getUint32(0);
  requireResource(offset + 4 + size <= data.size, "RCC payload exceeds data table");
  if (flags === 0) return { offset: data.offset + offset + 4, size };
  if (flags === 1) {
    requireResource(size >= 4, "Truncated qCompress size prefix");
    return { offset: data.offset + offset + 8, size: size - 4,
      uncompressedSize: (await readResource(reader, data, offset + 4, 4)).getUint32(0) };
  }
  return { offset: data.offset + offset + 4, size,
    uncompressedSize: resourceZstdSize(await readResource(reader, data, offset + 4, Math.min(size, 18))) };
};

const tableReader = (reader: FileRangeReader, names: ResourceRange, data: ResourceRange) => {
  // rcc deduplicates data and locale names. Cache each shared record within this tree parse.
  const nameCache = new Map<number, ReturnType<typeof readRccName>>();
  const payloadCache = new Map<string, ReturnType<typeof readPayload>>();
  return {
    name: (offset: number) => {
      const cached = nameCache.get(offset);
      if (cached) return cached;
      const value = readRccName(reader, names, offset);
      nameCache.set(offset, value);
      return value;
    },
    payload: (offset: number, flags: number) => {
      const key = `${offset}:${flags}`;
      const cached = payloadCache.get(key);
      if (cached) return cached;
      const value = readPayload(reader, data, offset, flags);
      payloadCache.set(key, value);
      return value;
    }
  };
};

const readNode = async (reader: FileRangeReader, tree: ResourceRange, tables: ReturnType<typeof tableReader>,
  nodeSize: number, index: number, parent: number | null): Promise<RccNode> => {
  const view = await readResource(reader, tree, index * nodeSize, nodeSize);
  const flags = view.getUint16(4);
  requireResource([0, 1, 2, 4].includes(flags), "Invalid RCC node flags");
  requireResource(index !== 0 || flags === 2, "RCC root is not a directory");
  const nameOffset = view.getUint32(0);
  const named = index === 0 ? null : await tables.name(nameOffset);
  const node: RccNode = { name: named?.name ?? "", parent, nameOffset, flags,
    ...(named ? { nameHash: named.hash } : {}),
    ...(nodeSize === 22 ? { timestamp: view.getBigUint64(14) } : {}) };
  if (flags === 2) return { ...node, childCount: view.getUint32(6), firstChild: view.getUint32(10) };
  return { ...node, territory: view.getUint16(6), language: view.getUint16(8),
    dataOffset: view.getUint32(10), payload: await tables.payload(view.getUint32(10), flags) };
};

export const readRccTree = async (reader: FileRangeReader, tree: ResourceRange,
  names: ResourceRange, data: ResourceRange, nodeSize: number): Promise<RccNode[]> => {
  const tables = tableReader(reader, names, data);
  const entries = [await readNode(reader, tree, tables, nodeSize, 0, null)];
  const pending = [0];
  const visited = new Set([0]);
  for (let cursor = 0; cursor < pending.length; cursor += 1) {
    const parent = pending[cursor]!;
    const node = entries[parent]!;
    if (node.flags !== 2) continue;
    const first = node.firstChild!;
    const count = node.childCount!;
    requireResource(first + count <= Math.floor(tree.size / nodeSize), "RCC child range exceeds tree");
    let previousHash = 0;
    const locales = new Set<string>();
    for (let index = first; index < first + count; index += 1) {
      requireResource(!visited.has(index), "RCC tree contains a cycle or shared child");
      visited.add(index);
      const child = await readNode(reader, tree, tables, nodeSize, index, parent);
      requireResource(child.nameHash! >= previousHash, "RCC children are not sorted by name hash");
      previousHash = child.nameHash!;
      const identity = JSON.stringify([child.name, child.territory, child.language]);
      requireResource(!locales.has(identity), "Duplicate RCC child and locale");
      locales.add(identity);
      entries[index] = child;
      pending.push(index);
    }
  }
  requireResource(entries.length === visited.size, "RCC tree contains unreachable nodes");
  return entries;
};
