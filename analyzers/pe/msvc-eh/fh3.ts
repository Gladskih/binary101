import { IMAGE_FILE_MACHINE_I386 } from "../../coff/machine.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../optional-header/magic.js";
import { FH3_LAYOUT } from "./layout.js";
import type { EhFunctionInfo, EhHandler, EhImage, EhTryBlock } from "./types.js";
import { ehCodeRva, ehMetadataRva, readEhTable, validCatchType, validEhState } from "./validation.js";

const readHandlers = async (image: EhImage, rva: number, count: number): Promise<EhHandler[] | null> => {
  // MSVC ehdata.h HandlerType on AMD64/ARM64 includes dispFrame at offset 16.
  // https://github.com/llvm/llvm-project/blob/main/llvm/lib/CodeGen/AsmPrinter/WinException.cpp
  const table = readEhTable(image, rva, count, image.core.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC
    ? FH3_LAYOUT.handlerEntrySize64 : FH3_LAYOUT.handlerEntrySize32);
  if (!table || count === 0) return null;
  const handlers: EhHandler[] = [];
  for (let index = 0; index < count; index++) {
    const row = await table.read(index);
    if (!row) return null;
    const typeDescriptorRva = ehMetadataRva(image, row.getUint32(4, true));
    const handlerRva = ehCodeRva(image, row.getUint32(12, true));
    if (!image.code(handlerRva) || !await validCatchType(image, typeDescriptorRva)) return null;
    handlers.push({ handlerRva, typeDescriptorRva, continuationRvas: [] });
  }
  return handlers;
};

const readTryBlocks = async (
  image: EhImage, rva: number, count: number, states: number
): Promise<EhTryBlock[] | null> => {
  const table = readEhTable(image, rva, count, FH3_LAYOUT.tryBlockEntrySize);
  if (!table) return null;
  const blocks: EhTryBlock[] = [];
  for (let index = 0; index < count; index++) {
    const row = await table.read(index);
    if (!row) return null;
    const tryLow = row.getInt32(0, true);
    const tryHigh = row.getInt32(4, true);
    const catchHigh = row.getInt32(8, true);
    if (tryLow < 0 || tryLow > tryHigh || tryHigh >= catchHigh || catchHigh >= states) return null;
    const handlers = await readHandlers(image, ehMetadataRva(image, row.getUint32(16, true)),
      row.getUint32(12, true));
    if (!handlers) return null;
    blocks.push({ tryLow, tryHigh, catchHigh, handlers });
  }
  return blocks;
};

const readHeader = async (image: EhImage, rva: number): Promise<DataView | null> => {
  // ehdata.h FuncInfo, EH_MAGIC_NUMBER3: 29-bit magic plus 3 BBT bits, 40-byte relative layout.
  const headerSize = image.core.coff.Machine === IMAGE_FILE_MACHINE_I386
    ? FH3_LAYOUT.absoluteFuncInfoSize : FH3_LAYOUT.relativeFuncInfoSize;
  const header = await image.read(rva, headerSize);
  if (!header || rva % FH3_LAYOUT.alignment ||
      (header.getUint32(0, true) & FH3_LAYOUT.magicMask) !== FH3_LAYOUT.magicNumber) return null;
  // Exception specifications and unknown flags require a different decoder; omit rather than guess.
  if (header.getUint32(headerSize - 8, true) !== 0 ||
      (header.getUint32(headerSize - 4, true) & ~FH3_LAYOUT.supportedEhFlags) !== 0) return null;
  return header;
};

const readUnwindActions = async (
  image: EhImage, rva: number, states: number
): Promise<EhFunctionInfo["unwindActions"] | null> => {
  const unwind = readEhTable(image, rva, states, FH3_LAYOUT.unwindEntrySize);
  if (!unwind) return null;
  const unwindActions: EhFunctionInfo["unwindActions"] = [];
  for (let index = 0; index < states; index++) {
    const row = await unwind.read(index);
    if (!row) return null;
    const toState = row.getInt32(0, true);
    const actionRva = ehCodeRva(image, row.getUint32(4, true));
    if (!validEhState(toState, index) || (actionRva !== 0 && !image.code(actionRva))) return null;
    unwindActions.push({ toState, actionRva });
  }
  return unwindActions;
};

const readIpStates = async (
  image: EhImage, rva: number, count: number, states: number
): Promise<EhFunctionInfo["ipStates"] | null> => {
  const ips = readEhTable(image, rva, count, FH3_LAYOUT.ipStateEntrySize);
  // LLVM's x86 FuncInfo reserves both IP-map fields as zero; table-based ABIs use real maps.
  if (!ips || ((image.core.coff.Machine === IMAGE_FILE_MACHINE_I386) !== (count === 0))) return null;
  const ipStates: EhFunctionInfo["ipStates"] = [];
  for (let index = 0; index < ips.count; index++) {
    const row = await ips.read(index);
    if (!row) return null;
    const ipRva = ehCodeRva(image, row.getUint32(0, true));
    const state = row.getInt32(4, true);
    if (!image.code(ipRva) || !validEhState(state, states) ||
        (ipStates.length > 0 && ipRva <= ipStates[ipStates.length - 1]!.ipRva)) return null;
    ipStates.push({ ipRva, state });
  }
  return ipStates;
};

const readFh3 = async (image: EhImage, rva: number): Promise<EhFunctionInfo | null> => {
  const header = await readHeader(image, rva);
  if (!header) return null;
  const states = header.getInt32(4, true);
  const unwindActions = await readUnwindActions(image, ehMetadataRva(image, header.getUint32(8, true)), states);
  if (!unwindActions) return null;
  const ipStates = await readIpStates(image, ehMetadataRva(image, header.getUint32(24, true)),
    header.getUint32(20, true), states);
  if (!ipStates) return null;
  const tryBlocks = await readTryBlocks(image, ehMetadataRva(image, header.getUint32(16, true)),
    header.getUint32(12, true), states);
  return tryBlocks ? { rva, version: 3, unwindActions, tryBlocks, ipStates } : null;
};

export const parseFh3 = (image: EhImage, rva: number): Promise<EhFunctionInfo | null> => {
  const key = `FH3:${rva}`;
  const cached = image.functionInfos.get(key);
  if (cached) return cached;
  const result = readFh3(image, rva);
  image.functionInfos.set(key, result);
  return result;
};
