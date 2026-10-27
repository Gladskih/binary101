import { FH4_FUNCTION_FLAGS } from "./layout.js";
import type { EhFunctionInfo, EhImage } from "./types.js";
import { EhCursor } from "./reader.js";
import { readFh4IpStates, readFh4TryBlocks, readFh4Unwind } from "./fh4-maps.js";

interface Fh4FunctionHeader { flags: number; unwindRva: number; tryRva: number; ipRva: number; }

const readSeparatedMap = async (
  image: EhImage, rva: number, states: number
): Promise<Map<number, EhFunctionInfo["ipStates"]> | null> => {
  const cursor = new EhCursor(image, rva);
  const count = await cursor.count(8);
  const maps = new Map<number, EhFunctionInfo["ipStates"]>();
  for (let index = 0; index < count; index++) {
    const start = await cursor.uint32();
    const mapRva = await cursor.uint32();
    if (!image.code(start) || maps.has(start)) return null;
    const map = await readFh4IpStates(image, mapRva, start, states);
    if (!map) return null;
    maps.set(start, map);
  }
  return cursor.valid ? maps : null;
};

const separatedMap = async (
  image: EhImage, rva: number, functionStart: number, states: number
): Promise<EhFunctionInfo["ipStates"] | null> => {
  // SepIPtoStateMap4 explicitly stores each contribution's RVA alongside its IP map.
  // Decode that complete shared graph once, preserving each entry's own relative base.
  // MSVC 14.51 ehdata4_export.h; https://devblogs.microsoft.com/cppblog/making-cpp-exception-handling-smaller-x64/
  const key = `${rva}:${states}`;
  let result = image.fh4SeparatedMaps.get(key);
  if (!result) {
    result = readSeparatedMap(image, rva, states);
    image.fh4SeparatedMaps.set(key, result);
  }
  return (await result)?.get(functionStart) ?? null;
};

const readHeader = async (image: EhImage, rva: number): Promise<Fh4FunctionHeader | null> => {
  const cursor = new EhCursor(image, rva);
  const header = await cursor.byte();
  if (header & FH4_FUNCTION_FLAGS.reserved) return null;
  if (header & FH4_FUNCTION_FLAGS.bbt) await cursor.compressed(); // BBT flags
  const unwindRva = header & FH4_FUNCTION_FLAGS.unwindMap ? await cursor.uint32() : 0;
  const tryRva = header & FH4_FUNCTION_FLAGS.tryBlockMap ? await cursor.uint32() : 0;
  const ipRva = await cursor.uint32();
  if (header & FH4_FUNCTION_FLAGS.isCatch) await cursor.compressed(); // catch funclet frame displacement
  return cursor.valid ? { flags: header, unwindRva, tryRva, ipRva } : null;
};

const validReferences = (header: Fh4FunctionHeader): boolean =>
  (!(header.flags & FH4_FUNCTION_FLAGS.unwindMap) || header.unwindRva !== 0) &&
  (!(header.flags & FH4_FUNCTION_FLAGS.tryBlockMap) || header.tryRva !== 0);

const readFh4 = async (
  image: EhImage, rva: number, functionStart: number
): Promise<EhFunctionInfo | null> => {
  const header = await readHeader(image, rva);
  if (!header || !validReferences(header)) return null;
  const unwindActions = await readFh4Unwind(image, header.unwindRva);
  if (!unwindActions) return null;
  const tryBlocks = await readFh4TryBlocks(image, header.tryRva, unwindActions.length, functionStart);
  if (!tryBlocks) return null;
  const ipStates = header.flags & FH4_FUNCTION_FLAGS.isSeparated
    ? await separatedMap(image, header.ipRva, functionStart, unwindActions.length)
    : await readFh4IpStates(image, header.ipRva, functionStart, unwindActions.length);
  return tryBlocks && ipStates ? { rva, version: 4, unwindActions, tryBlocks, ipStates } : null;
};

export const parseFh4 = (image: EhImage, rva: number, functionStart: number): Promise<EhFunctionInfo | null> => {
  const key = `FH4:${rva}:${functionStart}`;
  const cached = image.functionInfos.get(key);
  if (cached) return cached;
  const result = readFh4(image, rva, functionStart);
  image.functionInfos.set(key, result);
  return result;
};
