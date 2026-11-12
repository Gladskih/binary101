import { isPeWindowsParseResult, type PeParseResult } from "../../analyzers/pe/index.js";
import { IMAGE_FILE_MACHINE_TYPES } from "../../analyzers/coff/machine.js";
import { SUBSYSTEMS } from "../../analyzers/pe/constants.js";
import { hex } from "../../binary-utils.js";
import { overviewFact } from "../overview-card.js";

export const renderPeHeaderPreview = (pe: PeParseResult): string =>
  overviewFact("Machine", IMAGE_FILE_MACHINE_TYPES.find(([value]) => value === pe.coff.Machine)?.[1]
    ?? `Unknown (${hex(pe.coff.Machine, 4)})`) +
  (isPeWindowsParseResult(pe) && pe.opt ? overviewFact("Subsystem",
    SUBSYSTEMS.find(([value]) => value === pe.opt!.Subsystem)?.[1]
      ?? `Unknown (${hex(pe.opt.Subsystem, 4)})`) : "") +
  (pe.opt ? overviewFact("AddressOfEntryPoint", hex(pe.opt.AddressOfEntryPoint, 8)) : "");
