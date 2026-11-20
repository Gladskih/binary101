import type { DwarfFrames } from "../dwarf/frame-types.js";
import type { ElfUnwindSection } from "./unwind-types.js";

// Reuse the decoded debug-frame records; .eh_frame retains its ABI pointer encodings.
export const elfDwarfFrames = (frames: DwarfFrames, sectionIndex: number): ElfUnwindSection => ({
  sectionIndex, issues: [],
  cies: frames.cies.flatMap(({ encoding, ...cie }) => encoding ? [{ ...cie, ...encoding,
    fdeEncoding: 0, lsdaEncoding: 255, personality: null }] : []),
  fdes: frames.fdes.filter(fde => fde.segment == null || fde.segment === 0n).map(fde => ({
    offset: fde.offset, cieOffset: fde.cieOffset, start: { address: fde.start, indirect: false },
    range: fde.range, lsda: null, instructions: fde.instructions,
    ...(fde.instructionsIncomplete && { instructionsIncomplete: true })
  }))
});
