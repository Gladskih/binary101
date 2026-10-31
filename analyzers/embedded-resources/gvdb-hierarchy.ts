import type { GResourceItem } from "./types.js";
import { requireResource } from "./reader.js";

// GVDB uses signed UTF-8 bytes in djb_hash, unlike JavaScript string code units.
// https://gitlab.gnome.org/GNOME/gvdb/-/blob/main/gvdb/gvdb-builder.c (djb_hash)
const appendHash = (hash: number, name: string): number => {
  let value = hash;
  for (const byte of new TextEncoder().encode(name)) value = (value * 33 + (byte << 24 >> 24)) >>> 0;
  return value;
};

const validateHash = (entry: GResourceItem, index: number, buckets: number[],
  itemCount: number, bloomWords: number[], bloomShift: number): void => {
  const bucket = entry.hash % buckets.length;
  requireResource(index >= buckets[bucket]! && index < (buckets[bucket + 1] ?? itemCount),
    "GVDB item is in the wrong hash bucket");
  if (!bloomWords.length) return;
  const mask = (1 << (entry.hash & 31)) | (1 << ((entry.hash >>> bloomShift) & 31));
  requireResource((bloomWords[Math.floor(entry.hash / 32) % bloomWords.length]! & mask) === mask,
    "GVDB bloom filter excludes a resource");
};

const validateChildren = (entry: GResourceItem, index: number,
  entries: GResourceItem[], seen: Set<number>): number[] => {
  const names = new Set<string>();
  const children = entry.children ?? [];
  for (const child of children) {
    requireResource(child < entries.length && !seen.has(child), "GVDB child is invalid, shared or cyclic");
    const item = entries[child]!;
    requireResource(item.parent === index, "GVDB parent and child list disagree");
    requireResource(!names.has(item.name) && !item.name.slice(0, -1).includes("/"),
      "Duplicate or invalid GResource path component");
    names.add(item.name);
    seen.add(child);
  }
  return children;
};

export const validateGvdbHierarchy = (entries: GResourceItem[], buckets: number[],
  bloomWords: number[], bloomShift: number): void => {
  const roots = entries.flatMap((entry, index) => entry.parent === null ? [index] : []);
  requireResource(roots.length === 1 && entries[roots[0]!]!.name === "/", "GResource has no unique / root");
  const pending = [roots[0]!];
  const seen = new Set(pending);
  for (let cursor = 0; cursor < pending.length; cursor += 1) {
    const index = pending[cursor]!;
    const entry = entries[index]!;
    requireResource(entry.hash === appendHash(entry.parent === null ? 5381 : entries[entry.parent]!.hash,
      entry.name), "GVDB key hash mismatch");
    validateHash(entry, index, buckets, entries.length, bloomWords, bloomShift);
    requireResource(entry.type === "L" ? entry.name.endsWith("/") : !entry.name.endsWith("/"),
      "GResource key does not match its item type");
    for (const child of validateChildren(entry, index, entries, seen)) pending.push(child);
  }
  requireResource(seen.size === entries.length, "GVDB hierarchy contains unreachable items");
  requireResource(entries.some(entry => entry.type === "v"), "GVDB contains no GResource file values");
};
