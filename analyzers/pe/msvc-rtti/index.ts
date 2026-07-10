"use strict";

import { IMAGE_FILE_MACHINE_AMD64 } from "../../coff/machine.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeBaseRelocationResult } from "../directories/reloc.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../optional-header/magic.js";
import type { PeWindowsCore } from "../types.js";
import { discoverMsvcRtti } from "./discovery.js";
import { createMsvcRttiGraphParser } from "./graph-parser.js";
import { createMsvcRttiImage } from "./image.js";
import { indexMsvcRttiDir64Sites } from "./relocation-index.js";
import type { MsvcRttiAnalysis } from "./types.js";

export const analyzePeMsvcRtti = async (
  reader: FileRangeReader,
  core: PeWindowsCore,
  relocations: PeBaseRelocationResult | null
): Promise<MsvcRttiAnalysis | null> => {
  if (core.coff.Machine !== IMAGE_FILE_MACHINE_AMD64) return null;
  if (core.opt.Magic !== PE32_PLUS_OPTIONAL_HEADER_MAGIC) return null;
  try {
    const image = createMsvcRttiImage(
      reader,
      core.sections,
      core.opt.ImageBase,
      core.opt.SizeOfImage
    );
    const dir64Sites = indexMsvcRttiDir64Sites(relocations, image);
    return dir64Sites
      ? await discoverMsvcRtti(image, dir64Sites, createMsvcRttiGraphParser(image))
      : null;
  } catch {
    return null;
  }
};
