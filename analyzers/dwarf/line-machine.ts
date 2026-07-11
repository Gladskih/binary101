"use strict";

import {
  DWARF_LIMIT,
  DWARF_LINE_ENCODING,
  DWARF_LINE_EXTENDED_OPCODE,
  DWARF_LINE_STANDARD_OPCODE
} from "./constants.js";
import { DwarfCursor } from "./cursor.js";
import type { DwarfLineHeader } from "./line-header.js";
import type { DwarfLineFile, DwarfSectionSource } from "./types.js";

export type DwarfLineMachineResult = {
  addressSize: number;
  files: DwarfLineFile[];
  fileCount: number;
  rowCount: number;
  sequenceCount: number;
  minimumAddress: bigint | null;
  maximumAddress: bigint | null;
};

type MachineState = {
  address: bigint;
  operationIndex: bigint;
  sequenceOpen: boolean;
  rowCount: number;
  sequenceCount: number;
  minimumAddress: bigint | null;
  maximumAddress: bigint | null;
};

type LineMachineContext = {
  source: DwarfSectionSource;
  header: DwarfLineHeader;
  state: MachineState;
  files: DwarfLineFile[];
  fileCount: number;
  addressSize: number;
  littleEndian: boolean;
  issues: string[];
};

const KNOWN_EXTENDED_OPCODES = new Set<number>(Object.values(DWARF_LINE_EXTENDED_OPCODE));

const resetState = (state: MachineState): void => {
  state.address = DWARF_LINE_ENCODING.initialAddress;
  state.operationIndex = DWARF_LINE_ENCODING.initialOperationIndex;
  state.sequenceOpen = false;
};

const emitRow = (state: MachineState): void => {
  state.rowCount += 1;
  state.sequenceOpen = true;
  state.minimumAddress = state.minimumAddress == null || state.address < state.minimumAddress
    ? state.address
    : state.minimumAddress;
  state.maximumAddress = state.maximumAddress == null || state.address > state.maximumAddress
    ? state.address
    : state.maximumAddress;
};

const advanceAddress = (
  state: MachineState,
  header: DwarfLineHeader,
  operationAdvance: bigint
): void => {
  const maximumOperations = BigInt(header.maximumOperationsPerInstruction);
  const totalOperations = state.operationIndex + operationAdvance;
  state.address += BigInt(header.minimumInstructionLength) *
    (totalOperations / maximumOperations);
  state.operationIndex = totalOperations % maximumOperations;
};

const readLegacyFile = async (
  cursor: DwarfCursor
): Promise<DwarfLineFile | null> => {
  const path = await cursor.cstring();
  const directoryIndex = await cursor.uleb();
  const timestamp = await cursor.uleb();
  const size = await cursor.uleb();
  return path != null && directoryIndex != null && timestamp != null && size != null
    ? { path, directoryIndex }
    : null;
};

const readExtendedOpcode = async (
  cursor: DwarfCursor,
  context: LineMachineContext
): Promise<boolean> => {
  const encodedLength = await cursor.uleb();
  if (encodedLength == null || encodedLength === 0n ||
      encodedLength > BigInt(cursor.end - cursor.position)) {
    cursor.fail("Invalid extended line opcode length");
    return false;
  }
  const payloadEnd = cursor.position + Number(encodedLength);
  const payload = new DwarfCursor(
    context.source.reader,
    context.source.section,
    cursor.position,
    payloadEnd,
    context.littleEndian,
    context.issues
  );
  const opcode = await payload.uint8();
  if (opcode === DWARF_LINE_EXTENDED_OPCODE.endSequence) {
    emitRow(context.state);
    context.state.sequenceCount += 1;
    resetState(context.state);
  } else if (opcode === DWARF_LINE_EXTENDED_OPCODE.setAddress) {
    const operandSize = context.header.addressSize || payload.end - payload.position;
    if (operandSize < Uint8Array.BYTES_PER_ELEMENT ||
        operandSize > DWARF_LIMIT.maximumAddressBytes) {
      payload.fail(`Unsupported line address size ${operandSize}`);
      return false;
    }
    const value = await payload.unsigned(operandSize);
    if (value == null) return false;
    context.state.address = value;
    context.state.operationIndex = DWARF_LINE_ENCODING.initialOperationIndex;
    context.addressSize = operandSize;
  } else if (opcode === DWARF_LINE_EXTENDED_OPCODE.defineFile) {
    const file = await readLegacyFile(payload);
    if (!file) return false;
    context.fileCount += 1;
    if (context.files.length < DWARF_LIMIT.maximumLineFilesStored) context.files.push(file);
  } else if (opcode === DWARF_LINE_EXTENDED_OPCODE.setDiscriminator) {
    if (await payload.uleb() == null) return false;
  }
  if (payload.failed) return false;
  if (opcode != null && KNOWN_EXTENDED_OPCODES.has(opcode) &&
      payload.position !== payload.end) {
    payload.notice(`${payload.end - payload.position} trailing extended opcode bytes`);
  }
  cursor.position = payloadEnd;
  return true;
};

const skipDeclaredOperands = async (
  cursor: DwarfCursor,
  header: DwarfLineHeader,
  opcode: number
): Promise<boolean> => {
  const count = header.standardOperandCounts[
    opcode - DWARF_LINE_ENCODING.firstStandardOpcode
  ] ?? 0;
  for (let index = 0; index < count; index += 1) {
    if (await cursor.uleb() == null) return false;
  }
  return true;
};

const executeStandardOpcode = async (
  cursor: DwarfCursor,
  header: DwarfLineHeader,
  state: MachineState,
  opcode: number
): Promise<boolean> => {
  if (opcode === DWARF_LINE_STANDARD_OPCODE.copy) emitRow(state);
  else if (opcode === DWARF_LINE_STANDARD_OPCODE.advancePc) {
    const advance = await cursor.uleb();
    if (advance == null) return false;
    advanceAddress(state, header, advance);
  } else if (opcode === DWARF_LINE_STANDARD_OPCODE.advanceLine) {
    if (await cursor.sleb() == null) return false;
  } else if (opcode === DWARF_LINE_STANDARD_OPCODE.setFile ||
             opcode === DWARF_LINE_STANDARD_OPCODE.setColumn ||
             opcode === DWARF_LINE_STANDARD_OPCODE.setIsa) {
    if (await cursor.uleb() == null) return false;
  } else if (opcode === DWARF_LINE_STANDARD_OPCODE.constantAddPc) {
    advanceAddress(
      state,
      header,
      BigInt(Math.floor(
        (DWARF_LINE_ENCODING.maximumOpcode - header.opcodeBase) / header.lineRange
      ))
    );
  } else if (opcode === DWARF_LINE_STANDARD_OPCODE.fixedAdvancePc) {
    const advance = await cursor.uint16();
    if (advance == null) return false;
    state.address += BigInt(advance);
    state.operationIndex = DWARF_LINE_ENCODING.initialOperationIndex;
  } else if (opcode > DWARF_LINE_STANDARD_OPCODE.setIsa) {
    return skipDeclaredOperands(cursor, header, opcode);
  }
  return true;
};

const executeSpecialOpcode = (
  header: DwarfLineHeader,
  state: MachineState,
  opcode: number
): void => {
  const adjusted = opcode - header.opcodeBase;
  advanceAddress(state, header, BigInt(Math.floor(adjusted / header.lineRange)));
  emitRow(state);
};

export const executeDwarfLineProgram = async (
  source: DwarfSectionSource,
  header: DwarfLineHeader,
  littleEndian: boolean,
  issues: string[]
): Promise<DwarfLineMachineResult> => {
  const cursor = new DwarfCursor(
    source.reader, source.section, header.programOffset, header.end, littleEndian, issues
  );
  const state: MachineState = {
    address: DWARF_LINE_ENCODING.initialAddress,
    operationIndex: DWARF_LINE_ENCODING.initialOperationIndex,
    sequenceOpen: false,
    rowCount: 0,
    sequenceCount: 0,
    minimumAddress: null,
    maximumAddress: null
  };
  const context: LineMachineContext = {
    source,
    header,
    state,
    files: [...header.files],
    fileCount: header.fileCount,
    addressSize: header.addressSize,
    littleEndian,
    issues
  };
  let instructionCount = 0;
  while (!cursor.failed && cursor.position < cursor.end) {
    instructionCount += 1;
    if (instructionCount > DWARF_LIMIT.maximumLineInstructions) {
      cursor.fail(`Line program exceeds ${DWARF_LIMIT.maximumLineInstructions} instructions`);
      break;
    }
    const opcode = await cursor.uint8();
    if (opcode == null) break;
    const succeeded = opcode === DWARF_LINE_ENCODING.extendedOpcodeMarker
      ? await readExtendedOpcode(cursor, context)
      : opcode < header.opcodeBase
        ? await executeStandardOpcode(cursor, header, state, opcode)
        : (executeSpecialOpcode(header, state, opcode), true);
    if (!succeeded) break;
  }
  if (state.sequenceOpen) {
    cursor.notice("Line sequence has no DW_LNE_end_sequence terminator");
  }
  return {
    addressSize: context.addressSize,
    files: context.files,
    fileCount: context.fileCount,
    rowCount: state.rowCount,
    sequenceCount: state.sequenceCount,
    minimumAddress: state.minimumAddress,
    maximumAddress: state.maximumAddress
  };
};
