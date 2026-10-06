"use strict";

import { DWARF_LINE_EXTENDED_OPCODE as opcode } from "./constants.js";
import { DwarfCursor } from "./cursor.js";
import type { DwarfLineHeader } from "./line-header.js";
import { executeDwarfStandardLineOpcode } from "./line-opcodes.js";
import {
  advanceDwarfLineAddress, createDwarfLineRegisters, emitDwarfLineRow
} from "./line-registers.js";
import type { DwarfLineFile, DwarfLineRow, DwarfSectionSource } from "./types.js";

type LineMachine = {
  header: DwarfLineHeader;
  state: DwarfLineRow;
  rows: DwarfLineRow[];
  files: DwarfLineFile[];
  addressSize: number;
};

const readLegacyFile = async (cursor: DwarfCursor): Promise<DwarfLineFile | null> => {
  const path = await cursor.cstring();
  const directoryIndex = await cursor.uleb();
  const timestamp = await cursor.uleb();
  const size = await cursor.uleb();
  return path != null && directoryIndex != null && timestamp != null && size != null
    ? { path, directoryIndex, timestamp, size } : null;
};

const readSetAddress = async (cursor: DwarfCursor, machine: LineMachine): Promise<void> => {
  const operandSize = machine.header.addressSize || cursor.end - cursor.position;
  const value = await cursor.unsigned(operandSize);
  if (value == null) return;
  if (machine.addressSize && machine.addressSize !== operandSize) {
    cursor.notice("Inconsistent address widths in one line program");
  }
  machine.state.address = value;
  machine.state.operationIndex = 0n;
  machine.addressSize = operandSize;
};

const executeExtendedOpcode = async (
  cursor: DwarfCursor, machine: LineMachine
): Promise<void> => {
  const code = await cursor.uint8();
  if (code === opcode.endSequence) {
    machine.state.endSequence = true;
    emitDwarfLineRow(machine.rows, machine.state);
    machine.state = createDwarfLineRegisters(machine.header);
  } else if (code === opcode.setAddress) await readSetAddress(cursor, machine);
  else if (code === opcode.defineFile) {
    const file = await readLegacyFile(cursor);
    if (file) machine.files.push(file);
  } else if (code === opcode.setDiscriminator) {
    const value = await cursor.uleb();
    if (value != null) machine.state.discriminator = value;
  } else if (code != null) {
    cursor.notice(`Unknown extended line opcode ${code}; skipping its payload`);
    cursor.skip(cursor.end - cursor.position);
  }
  noticeTrailingPayload(cursor);
};

const noticeTrailingPayload = (cursor: DwarfCursor): void => {
  if (!cursor.failed && cursor.position !== cursor.end) {
    cursor.notice(`${cursor.end - cursor.position} trailing extended opcode bytes`);
  }
};

const executeSpecialOpcode = (machine: LineMachine, code: number): void => {
  const adjusted = code - machine.header.opcodeBase;
  advanceDwarfLineAddress(
    machine.state, machine.header, BigInt(Math.floor(adjusted / machine.header.lineRange))
  );
  machine.state.line += BigInt(machine.header.lineBase + adjusted % machine.header.lineRange);
  emitDwarfLineRow(machine.rows, machine.state);
};

const readExtendedOpcode = async (
  cursor: DwarfCursor, source: DwarfSectionSource, machine: LineMachine,
  littleEndian: boolean, issues: string[]
): Promise<boolean> => {
  const length = await cursor.uleb();
  if (length == null || length === 0n || length > BigInt(cursor.end - cursor.position)) {
    cursor.fail("Invalid extended line opcode length");
    return false;
  }
  const payload = new DwarfCursor(source.reader, source.section,
    cursor.position, cursor.position + Number(length), littleEndian, issues);
  await executeExtendedOpcode(payload, machine);
  cursor.position = payload.end;
  return !payload.failed;
};

const executeOpcode = async (cursor: DwarfCursor, source: DwarfSectionSource,
  machine: LineMachine, code: number, littleEndian: boolean, issues: string[]): Promise<boolean> => {
  if (code === 0) return readExtendedOpcode(cursor, source, machine, littleEndian, issues);
  if (code < machine.header.opcodeBase) {
    return executeDwarfStandardLineOpcode(cursor, machine.header, machine.state, machine.rows, code);
  }
  executeSpecialOpcode(machine, code);
  return true;
};

export const executeDwarfLineProgram = async (
  source: DwarfSectionSource, header: DwarfLineHeader,
  littleEndian: boolean, issues: string[]
): Promise<{ addressSize: number; files: DwarfLineFile[]; rows: DwarfLineRow[] }> => {
  const cursor = new DwarfCursor(
    source.reader, source.section, header.programOffset, header.end, littleEndian, issues
  );
  const machine: LineMachine = {
    header, state: createDwarfLineRegisters(header), rows: [],
    files: [...header.files], addressSize: header.addressSize
  };
  while (!cursor.failed && cursor.position < cursor.end) {
    const code = await cursor.uint8();
    if (code == null) break;
    if (!await executeOpcode(cursor, source, machine, code, littleEndian, issues)) break;
  }
  if (machine.rows.length && !machine.rows.at(-1)?.endSequence) {
    cursor.notice("Line sequence has no DW_LNE_end_sequence terminator");
  }
  return { addressSize: machine.addressSize, files: machine.files, rows: machine.rows };
};
