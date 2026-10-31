import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { basename } from "node:path";
import { createInterface } from "node:readline";
import { Readable } from "node:stream";
import { parsePe } from "../analyzers/pe/index.js";
import { parseElf } from "../analyzers/elf/index.js";
import { createFileRangeReader } from "../analyzers/file-range-reader.js";
import type { FileRangeReader } from "../analyzers/file-range-reader.js";
import { readEmbeddedResourceContent } from "../analyzers/embedded-resources/content.js";
import { resolveResourcePayload } from "../analyzers/embedded-resources/payload.js";
import type { EmbeddedResource, EmbeddedResourceEntry, RccResource, ResourcePayload }
  from "../analyzers/embedded-resources/types.js";
import { createDiskBackedFile } from "./pe-import-metadata-scan/disk-file.js";

const diskFile = async (path: string): Promise<File> => {
  const base = createDiskBackedFile(path, (await stat(path)).size);
  return { ...base, name: basename(path), slice: (start = 0, end = base.size) => ({
    ...base.slice(start, end), stream: () => end > start
      ? Readable.toWeb(createReadStream(path, { start, end: end - 1 }))
      : new ReadableStream({ start: controller => controller.close() })
  }) } as File;
};

const entryPath = (resource: EmbeddedResource, index: number): string => {
  const components: string[] = [];
  let current: number | null = index;
  while (current !== null) {
    const entry: EmbeddedResourceEntry = resource.entries[current]!;
    if (entry.name) components.push(entry.name);
    current = entry.parent;
  }
  return `/${components.reverse().join("/")}`;
};

type ContentDigest = { sha256: string; issues: string[] };

const digestPayload = async (reader: FileRangeReader, payload: ResourcePayload,
  cache: Map<string, ContentDigest>): Promise<ContentDigest> => {
  const key = JSON.stringify([payload.offset, payload.size, payload.compression, payload.uncompressedSize]);
  const cached = cache.get(key);
  if (cached) return cached;
  const content = await readEmbeddedResourceContent(reader, payload, 64 * 1024 * 1024);
  const result = { sha256: content.value ? createHash("sha256").update(content.value).digest("hex") : "",
    issues: content.issues };
  cache.set(key, result);
  return result;
};

const describeBundle = async (reader: FileRangeReader, resource: RccResource, offset: number,
  cache: Map<string, ContentDigest>) => {
  const files = [];
  for (const [index, entry] of resource.entries.entries()) {
    const payload = resolveResourcePayload(resource.format, entry);
    if (!payload) continue;
    files.push({ path: entryPath(resource, index), offset: payload.offset, size: payload.size,
      ...await digestPayload(reader, payload, cache), language: entry.language, territory: entry.territory });
  }
  return { offset, tree: resource.tree, names: resource.names, data: resource.data,
    version: resource.version, format: resource.format, files };
};

const parseFile = async (file: File) => {
  const header = new Uint8Array(await file.slice(0, 4).arrayBuffer());
  const parsed = header[0] === 77 && header[1] === 90 ? await parsePe(file) : await parseElf(file);
  if (!parsed) throw new Error("Unsupported input");
  return parsed;
};

const scan = async (path: string) => {
  const file = await diskFile(path);
  const parsed = await parseFile(file);
  const reader = createFileRangeReader(file, 0, file.size);
  const cache = new Map<string, ContentDigest>();
  const bundles = [];
  for (const bundle of parsed.embeddedResources?.bundles ?? []) {
    if (bundle.resource.format === "Qt RCC") {
      bundles.push(await describeBundle(reader, bundle.resource, bundle.offset, cache));
    }
  }
  return { bundles, issues: parsed.embeddedResources?.issues ?? [] };
};

for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  let id = "";
  try {
    const request = JSON.parse(line) as { id?: unknown; path?: unknown };
    if (typeof request.id !== "string" || typeof request.path !== "string") {
      throw new Error("Expected { id: string, path: string }");
    }
    id = request.id;
    process.stdout.write(`${JSON.stringify({ id, status: "ok", ...await scan(request.path) })}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ id, status: "error", error: String(error) })}\n`);
  }
}
