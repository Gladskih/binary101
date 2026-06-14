"use strict";

import { parseCodeSignature } from "./codesign.js";
import { parseSymtab } from "./symbol-table.js";
import type { ThinExternalData, ThinLoadCommandState } from "./thin-load-command-state.js";
import type { MachOEntryPoint, MachOFileHeader } from "./types.js";

export const parseThinExternalData = async (
  file: File,
  imageOffset: number,
  imageSize: number,
  header: MachOFileHeader,
  state: ThinLoadCommandState,
  issues: string[]
): Promise<ThinExternalData> => {
  state.entryPoint = resolveThinEntryPoint(state.entryPoint);
  const symtab = state.symtabCommand
    ? await parseSymtab(
        file,
        imageOffset,
        imageSize,
        header,
        state.symtabCommand.symoff,
        state.symtabCommand.nsyms,
        state.symtabCommand.stroff,
        state.symtabCommand.strsize
      )
    : null;
  if (symtab?.issues.length) issues.push(...symtab.issues);
  const codeSignature = state.codeSignatureCommand
    ? await parseCodeSignature(
        file,
        imageOffset,
        imageSize,
        state.codeSignatureCommand.loadCommandIndex,
        state.codeSignatureCommand.dataoff,
        state.codeSignatureCommand.datasize
      )
    : null;
  if (codeSignature?.issues.length) issues.push(...codeSignature.issues);
  return { symtab, codeSignature };
};

const resolveThinEntryPoint = (
  entryPoint: ThinLoadCommandState["entryPoint"]
): MachOEntryPoint | null => {
  if (entryPoint == null) return null;
  return {
    loadCommandIndex: entryPoint.loadCommandIndex,
    entryoff: entryPoint.entryoff,
    stacksize: entryPoint.stacksize
  };
};
