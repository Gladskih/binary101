import { DwarfStringReader } from "./strings.js";
import { DwarfCursor } from "./cursor.js";
import { readDwarfLineTables } from "./line-tables.js";
import type { DwarfSectionSource } from "./types.js";

const readBytes = async (cursor: DwarfCursor, count: number): Promise<number[] | null> => {
  const bytes: number[] = [];
  for (let index = 0; index < count; index += 1) {
    const byte = await cursor.uint8();
    if (byte == null) return null;
    bytes.push(byte);
  }
  return bytes;
};

const readMachineParameters = async (cursor: DwarfCursor, version: number) => {
  const bytes = await readBytes(cursor, version >= 4 ? 6 : 5);
  if (!bytes) return null;
  if (version < 4) bytes.splice(1, 0, 1);
  // DWARF 5 6.2.4: line_base is signed, unlike the remaining one-byte parameters.
  // https://dwarfstd.org/doc/DWARF5.pdf
  const [minimumInstructionLength, maximumOperationsPerInstruction, defaultIsStatement,
    lineBase, lineRange, opcodeBase] = bytes as [number, number, number, number, number, number];
  if ([minimumInstructionLength, maximumOperationsPerInstruction, lineRange, opcodeBase].includes(0)) {
    cursor.fail("Line header contains a zero divisor or opcode base");
    return null;
  }
  return { minimumInstructionLength, maximumOperationsPerInstruction,
    defaultIsStatement: defaultIsStatement !== 0,
    lineBase: Number(BigInt.asIntN(8, BigInt(lineBase))), lineRange, opcodeBase };
};

export const readDwarfLinePrologue = async (
  source: DwarfSectionSource, cursor: DwarfCursor, version: number, format: 32 | 64,
  sections: Map<string, DwarfSectionSource>, byteOrder: "little" | "big", issues: string[], strings = new DwarfStringReader(sections, byteOrder, issues)
) => {
  const length = await cursor.unsigned(format / 8);
  if (length == null) return null;
  if (length > BigInt(cursor.end - cursor.position)) {
    cursor.fail("Line header extends beyond its program");
    return null;
  }
  const header = new DwarfCursor(source.reader, source.section, cursor.position,
    cursor.position + Number(length), byteOrder === "little", issues);
  const parameters = await readMachineParameters(header, version);
  if (!parameters) return null;
  const standardOperandCounts = await readBytes(header, parameters.opcodeBase - 1);
  if (!standardOperandCounts) return null;
  const tables = await readDwarfLineTables(header, version, {
    sections, littleEndian: byteOrder === "little", issues, dwarfFormat: format, strings
  });
  if (!tables || header.failed) return null;
  if (header.position !== header.end) {
    header.notice(`${header.end - header.position} unparsed line header bytes`);
  }
  return { ...parameters, ...tables, standardOperandCounts, programOffset: header.end };
};
