import type { FileRangeReader } from "../file-range-reader.js";
import type { RccResource, ResourceDecodeResult, ResourceRange } from "./types.js";
import { inspectResource, readResource, requireResource } from "./reader.js";
import { readRccTree } from "./rcc-tree.js";

const tableRange = (base: number, size: number, offset: number, offsets: number[]): ResourceRange =>
  ({ offset: base + offset, size: Math.min(size, ...offsets.filter(next => next > offset)) - offset });

const validateOffsets = (offsets: number[], headerSize: number, size: number): void => {
  requireResource((new Set(offsets).size === 3 || offsets.every(value => value === offsets[0])) &&
    offsets.every(value => value >= headerSize && value <= size), "Invalid RCC table offsets");
};

const validateCompression = (resource: RccResource): void => {
  requireResource(resource.version === 3 || resource.entries.every(entry => entry.flags !== 4),
    "Zstandard requires RCC v3");
  requireResource(resource.flags === undefined || resource.entries.every(entry =>
    entry.flags === 2 || (entry.flags & resource.flags!) === entry.flags),
  "RCC compression is absent from feature flags");
};

const readFlags = async (reader: FileRangeReader, range: ResourceRange, version: number) => {
  if (version !== 3) return undefined;
  const flags = (await readResource(reader, range, 20, 4)).getUint32(0);
  requireResource((flags & ~5) === 0, "Unsupported RCC feature flags");
  return flags;
};

export const decodeRcc = (reader: FileRangeReader, offset: number, size: number
): Promise<ResourceDecodeResult<RccResource>> => inspectResource(async () => {
  const range = { offset, size };
  const header = await readResource(reader, range, 0, 20);
  requireResource(header.getUint32(0) === 0x71726573, "Invalid qres signature");
  const version = header.getUint32(4);
  requireResource(version >= 1 && version <= 3, "Unsupported RCC version");
  const offsets = [header.getUint32(8), header.getUint32(12), header.getUint32(16)];
  validateOffsets(offsets, version === 3 ? 24 : 20, size);
  const flags = await readFlags(reader, range, version);
  const tree = tableRange(offset, size, offsets[0]!, offsets);
  const data = tableRange(offset, size, offsets[1]!, offsets);
  const names = tableRange(offset, size, offsets[2]!, offsets);
  const nodeSize = version === 1 ? 14 : 22;
  const entries = await readRccTree(reader, tree, names, data, nodeSize);
  requireResource(new Set(offsets).size === 3 || entries.length === 1, "Nonempty RCC tables overlap");
  const resource: RccResource = { format: "Qt RCC", version, ...(flags === undefined ? {} : { flags }),
    tree: { ...tree, size: entries.length * nodeSize },
    names: { ...names, size: offsets[2] === offsets[0] ? 0 : names.size },
    data: { ...data, size: offsets[1] === offsets[0] ? 0 : data.size }, entries };
  validateCompression(resource);
  return resource;
});

export const decodeRccArrays = (reader: FileRangeReader, tree: ResourceRange,
  names: ResourceRange, data: ResourceRange): Promise<ResourceDecodeResult<RccResource>> =>
  inspectResource(async () => {
    const matches: RccResource[] = [];
    for (const nodeSize of [14, 22]) {
      const decoded = await inspectResource(() => readRccTree(reader, tree, names, data, nodeSize));
      if (!decoded.value) continue;
      if (nodeSize === 14 && decoded.value.some(entry => entry.flags === 4)) continue;
      matches.push({ format: "Qt RCC", version: nodeSize === 14 ? 1 : null,
        tree: { ...tree, size: decoded.value.length * nodeSize },
        names, data, entries: decoded.value });
    }
    requireResource(matches.length === 1, "RCC array layout is invalid or ambiguous");
    return matches[0]!;
  });
