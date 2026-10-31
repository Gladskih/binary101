import type { FileRangeReader } from "../file-range-reader.js";
import type { GResourceItem, ResourceRange } from "./types.js";
import { readResource, requireResource, resourceBytes, validResourceRange } from "./reader.js";

// GVDB metadata is always LE, including files whose GVariant values are byte-swapped.
// https://gitlab.gnome.org/GNOME/gvdb/-/blob/main/gvdb/gvdb-format.h
// https://gitlab.gnome.org/GNOME/gvdb/-/blob/main/gvdb/gvdb-reader.c
const readWords = async (reader: FileRangeReader, range: ResourceRange,
  offset: number, count: number): Promise<number[]> => {
  requireResource(validResourceRange(offset, count * 4, range.size), "GVDB word array exceeds table");
  const words: number[] = [];
  for (let index = 0; index < count; index += 1) {
    words.push((await readResource(reader, range, offset + index * 4, 4)).getUint32(0, true));
  }
  return words;
};

const requireOutsideTable = (start: number, end: number, root: ResourceRange): void => {
  requireResource(end <= root.offset || start >= root.offset + root.size,
    "GVDB key or value overlaps the hash table");
};

const valueRange = (view: DataView, type: string, range: ResourceRange, root: ResourceRange): ResourceRange => {
  const start = view.getUint32(16, true);
  const end = view.getUint32(20, true);
  requireResource(start >= 24 && start % (type === "v" ? 8 : 4) === 0 &&
    validResourceRange(start, end - start, range.size), "Invalid GVDB value pointer");
  requireOutsideTable(start, end, root);
  return { offset: range.offset + start, size: end - start };
};

const readItem = async (reader: FileRangeReader, range: ResourceRange,
  root: ResourceRange, offset: number): Promise<GResourceItem> => {
  const view = await readResource(reader, range, offset, 24);
  const keyOffset = view.getUint32(8, true);
  const keySize = view.getUint16(12, true);
  const type = String.fromCharCode(view.getUint8(14));
  requireResource(type === "L" || type === "v", "GVDB item is not a GResource directory or value");
  requireResource(view.getUint8(15) === 0, "Nonzero GVDB reserved byte");
  const value = valueRange(view, type, range, root);
  requireResource(keyOffset >= 24 && validResourceRange(keyOffset, keySize, range.size),
    "Invalid GVDB key pointer");
  requireOutsideTable(keyOffset, keyOffset + keySize, root);
  const name = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(resourceBytes(
    await readResource(reader, range, keyOffset, keySize)));
  requireResource(name.length > 0 && !name.includes("\0"), "Invalid GVDB key");
  return { name, parent: view.getUint32(4, true) === 0xffffffff ? null : view.getUint32(4, true),
    hash: view.getUint32(0, true), keyOffset: range.offset + keyOffset, keySize,
    type: type as "L" | "v", value };
};

export const readGvdbTable = async (reader: FileRangeReader, range: ResourceRange,
  root: ResourceRange): Promise<{
    bloomShift: number; bloomWords: number[]; buckets: number[]; entries: GResourceItem[]
  }> => {
  requireResource(root.offset >= 24 && root.offset % 4 === 0 && root.size >= 8,
    "Invalid GVDB root pointer");
  const header = await readResource(reader, range, root.offset, 8);
  const bloom = header.getUint32(0, true);
  const bucketCount = header.getUint32(4, true);
  // The high five bits hold bloom_shift; low 27 bits hold the word count.
  const bloomCount = bloom & 0x07ffffff;
  const itemOffset = root.offset + 8 + (bloomCount + bucketCount) * 4;
  const itemBytes = root.offset + root.size - itemOffset;
  requireResource(itemBytes >= 0 && itemBytes % 24 === 0 && bucketCount > 0,
    "Invalid GVDB hash table dimensions");
  await readResource(reader, range, root.offset + root.size, 0);
  const table = { offset: range.offset + root.offset, size: root.size };
  const bloomWords = await readWords(reader, table, 8, bloomCount);
  const buckets = await readWords(reader, table, 8 + bloomCount * 4, bucketCount);
  const entries: GResourceItem[] = [];
  for (let index = 0; index < itemBytes / 24; index += 1) {
    entries.push(await readItem(reader, range, root, itemOffset + index * 24));
  }
  requireResource(buckets[0] === 0 && buckets.every((bucket, index) =>
    bucket <= entries.length && (index === 0 || bucket >= buckets[index - 1]!)),
  "GVDB buckets are not ordered or exceed item count");
  return { bloomShift: bloom >>> 27, bloomWords, buckets, entries };
};

export const readGvdbChildren = async (reader: FileRangeReader, item: GResourceItem): Promise<number[]> => {
  requireResource(item.value.size % 4 === 0, "GVDB child list is not a uint32 array");
  return readWords(reader, item.value, 0, item.value.size / 4);
};
