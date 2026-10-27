import { FH4_HANDLER_FLAGS, FH4_UNWIND_TYPE } from "./layout.js";
import type { EhFunctionInfo, EhHandler, EhImage, EhTryBlock } from "./types.js";
import { EhCursor } from "./reader.js";
import { validCatchType, validEhState } from "./validation.js";

// MSVC 14.51 include/ehdata4_export.h: UWMap4, HandlerMap4, TryBlockMap4, IPtoStateMap4.
// https://devblogs.microsoft.com/cppblog/making-cpp-exception-handling-smaller-x64/
const readUnwindAction = async (
  image: EhImage, cursor: EhCursor, type: number
): Promise<number | null> => {
  if (type === FH4_UNWIND_TYPE.none) return 0;
  const action = await cursor.uint32();
  if (type === FH4_UNWIND_TYPE.object || type === FH4_UNWIND_TYPE.objectPointer) await cursor.compressed();
  return cursor.valid && image.code(action) ? action : null;
};

const decodeUnwindMap = async (
  image: EhImage, rva: number
): Promise<EhFunctionInfo["unwindActions"] | null> => {
  if (!rva) return [];
  const cursor = new EhCursor(image, rva);
  const count = await cursor.count(1);
  const start = cursor.position;
  const entryStates = new Map<number, number>();
  const actions: EhFunctionInfo["unwindActions"] = [];
  for (let index = 0; index < count; index++) {
    const position = cursor.position;
    const encoded = await cursor.compressed();
    const target = position - Math.floor(encoded / 4);
    const toState = target < start ? -1 : entryStates.get(target);
    if (toState == null || target >= position) return null;
    const type = encoded & FH4_UNWIND_TYPE.funclet;
    const actionRva = await readUnwindAction(image, cursor, type);
    if (actionRva == null) return null;
    entryStates.set(position, index);
    actions.push({ toState, actionRva });
  }
  return cursor.valid && count > 0 ? actions : null;
};

export const readFh4Unwind = (image: EhImage, rva: number): Promise<EhFunctionInfo["unwindActions"] | null> => {
  // FH4 shares this map across COMDAT-folded functions; unlike IP and continuation
  // offsets its contents do not depend on the owner's BeginAddress.
  // https://devblogs.microsoft.com/cppblog/making-cpp-exception-handling-smaller-x64/
  const cached = image.fh4UnwindMaps.get(rva);
  if (cached) return cached;
  const result = decodeUnwindMap(image, rva);
  image.fh4UnwindMaps.set(rva, result);
  return result;
};

const readContinuations = async (
  image: EhImage, cursor: EhCursor, header: number, functionStart: number
): Promise<number[] | null> => {
  const continuationCount = (header >>> FH4_HANDLER_FLAGS.continuationCountShift) &
    FH4_HANDLER_FLAGS.continuationCountMask;
  const continuationRvas: number[] = [];
  for (let index = 0; index < continuationCount; index++) {
    const target = header & FH4_HANDLER_FLAGS.continuationsAreRvas
      ? await cursor.uint32() : functionStart + await cursor.compressed();
    if (!image.code(target)) return null;
    continuationRvas.push(target);
  }
  return cursor.valid ? continuationRvas : null;
};

const readHandler = async (
  image: EhImage, cursor: EhCursor, functionStart: number
): Promise<EhHandler | null> => {
  const header = await cursor.byte();
  if ((header & FH4_HANDLER_FLAGS.reserved) !== 0 ||
      ((header >>> FH4_HANDLER_FLAGS.continuationCountShift) & FH4_HANDLER_FLAGS.continuationCountMask) === 3) {
    return null;
  }
  if (header & FH4_HANDLER_FLAGS.adjectives) await cursor.compressed();
  const typeDescriptorRva = header & FH4_HANDLER_FLAGS.type ? await cursor.uint32() : 0;
  if (header & FH4_HANDLER_FLAGS.catchObject) await cursor.compressed();
  const handlerRva = await cursor.uint32();
  if (!image.code(handlerRva) || !await validCatchType(image, typeDescriptorRva)) return null;
  const continuationRvas = await readContinuations(image, cursor, header, functionStart);
  return continuationRvas ? { handlerRva, typeDescriptorRva, continuationRvas } : null;
};

export const readFh4Handlers = async (
  image: EhImage, rva: number, functionStart: number
): Promise<EhHandler[] | null> => {
  const cursor = new EhCursor(image, rva);
  const count = await cursor.count(5);
  const handlers: EhHandler[] = [];
  for (let index = 0; index < count; index++) {
    const handler = await readHandler(image, cursor, functionStart);
    if (!handler) return null;
    handlers.push(handler);
  }
  return cursor.valid && count > 0 ? handlers : null;
};

export const readFh4TryBlocks = async (
  image: EhImage, rva: number, states: number, functionStart: number
): Promise<EhTryBlock[] | null> => {
  if (!rva) return [];
  const cursor = new EhCursor(image, rva);
  const count = await cursor.count(7);
  const blocks: EhTryBlock[] = [];
  for (let index = 0; index < count; index++) {
    const tryLow = await cursor.compressed();
    const tryHigh = await cursor.compressed();
    const catchHigh = await cursor.compressed();
    if (tryLow > tryHigh || tryHigh >= catchHigh || catchHigh >= states) return null;
    const handlers = await readFh4Handlers(image, await cursor.uint32(), functionStart);
    if (!handlers) return null;
    blocks.push({ tryLow, tryHigh, catchHigh, handlers });
  }
  return cursor.valid && count > 0 ? blocks : null;
};

export const readFh4IpStates = async (
  image: EhImage, rva: number, functionStart: number, states: number
): Promise<EhFunctionInfo["ipStates"] | null> => {
  const cursor = new EhCursor(image, rva);
  const count = await cursor.count(2);
  const entries: EhFunctionInfo["ipStates"] = [];
  let ipRva = functionStart;
  for (let index = 0; index < count; index++) {
    const delta = await cursor.compressed();
    ipRva += delta;
    const state = await cursor.compressed() - 1;
    if (!image.code(ipRva) || (index > 0 && delta === 0) || !validEhState(state, states)) return null;
    entries.push({ ipRva, state });
  }
  return cursor.valid && count > 0 ? entries : null;
};
