import { dwarfUnitRoot } from "./attribute-values.js";
import type { DwarfLineProgram, DwarfLineRow, DwarfUnit } from "./types.js";

const validFile = (program: DwarfLineProgram, index: bigint): boolean => {
  // DWARF 5 6.2.4 changes the file table from one-based to zero-based indices.
  // https://dwarfstd.org/doc/DWARF5.pdf
  const first = program.version >= 5 ? 0n : 1n;
  return index >= first && index - first < BigInt(program.files.length);
};

const validateRow = (program: DwarfLineProgram, row: DwarfLineRow,
  previous: DwarfLineRow | null, issues: string[]): void => {
  if (!row.endSequence && !validFile(program, row.file)) {
    issues.push(`.debug_line: row references missing source file ${row.file}.`);
  }
  if (row.line < 0n) issues.push(`.debug_line: negative source line ${row.line}.`);
  if (previous && (row.address < previous.address ||
      (row.address === previous.address && row.operationIndex < previous.operationIndex))) {
    issues.push(".debug_line: source mappings move backwards within a code sequence.");
  }
};

const validateDirectories = (program: DwarfLineProgram, issues: string[]): void => {
  for (const file of program.files) {
      const index = file.directoryIndex;
      const first = program.version >= 5 ? 0n : 1n;
      if (index != null && (index !== 0n || program.version >= 5) &&
          (index < first || index - first >= BigInt(program.directories.length))) {
        issues.push(`.debug_line: ${file.path} references missing directory ${index}.`);
      }
  }
};

export const validateDwarfLines = (
  programs: DwarfLineProgram[], units: DwarfUnit[], issues: string[]
): void => {
  for (const program of programs) {
    validateDirectories(program, issues);
    let previous: DwarfLineRow | null = null;
    for (const row of program.rows) {
      validateRow(program, row, previous, issues);
      previous = row.endSequence ? null : row;
    }
  }
  validateStatementLists(programs, units, issues);
};

const validateStatementLists = (
  programs: DwarfLineProgram[], units: DwarfUnit[], issues: string[]
): void => {
  const offsets = new Set(programs.map(program => BigInt(program.offset)));
  for (const unit of units) {
    const offset = dwarfUnitRoot(unit)?.statementListOffset;
    if (offset != null && !offsets.has(offset)) {
      issues.push(`${unit.sectionName}: statement list ${offset} does not identify a line program.`);
    }
  }
};
