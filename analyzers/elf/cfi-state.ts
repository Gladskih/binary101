import { evaluateDwarfCfi } from "../dwarf/cfi-state.js";
import type { ElfUnwindCie, ElfUnwindFde } from "./unwind-types.js";
import type { ElfCfiEvaluation } from "./cfi-state-types.js";

export const evaluateElfCfi = (cie: ElfUnwindCie, fde: ElfUnwindFde): ElfCfiEvaluation =>
  evaluateDwarfCfi(cie, { ...fde, start: fde.start && !fde.start.indirect ? fde.start.address : null });
