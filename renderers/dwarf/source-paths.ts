import type { DwarfLineFile, DwarfLineProgram, DwarfUnit } from "../../analyzers/dwarf/types.js";
import { dwarfUnitRoot } from "../../analyzers/dwarf/attribute-values.js";

const isAbsolutePath = (path: string): boolean => /^(?:\/|\\|[A-Za-z]:[\\/])/.test(path);

const joinPath = (directory: string, path: string): string =>
  !directory || isAbsolutePath(path) ? path : `${directory.replace(/[\\/]$/, "")}/${path}`;

export const dwarfSourcePath = (
  program: DwarfLineProgram, file: DwarfLineFile, unit: DwarfUnit | undefined
): string => {
  const compilationDirectory = dwarfUnitRoot(unit)?.compilationDirectory ?? "";
  const directoryIndex = file.directoryIndex == null ? null
    : Number(file.directoryIndex) - (program.version < 5 ? 1 : 0);
  const directory = directoryIndex == null ? ""
    : program.directories[directoryIndex] ?? "";
  return joinPath(joinPath(compilationDirectory, directory), file.path);
};

export const dwarfLineFile = (
  program: DwarfLineProgram, fileIndex: bigint
): DwarfLineFile | undefined => {
  if (fileIndex < 0n || fileIndex > BigInt(Number.MAX_SAFE_INTEGER)) return undefined;
  return program.files[Number(fileIndex) - (program.version < 5 ? 1 : 0)];
};
