"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { NativeAotMetadata } from "../native-aot/format.js";
import { findNativeAotMetadata } from "../native-aot/ready-to-run.js";
import type { PeBaseRelocationResult } from "./directories/reloc.js";
import {
  createPeNativeAotImage,
  getPeNativeAotArchitecture,
  indexPeNativeAotPointerSites
} from "./native-aot/image.js";
import type { PeWindowsCore } from "./types.js";

export const analyzePeNativeAotMetadata = async (
  reader: FileRangeReader,
  core: PeWindowsCore,
  relocations: PeBaseRelocationResult | null
): Promise<NativeAotMetadata | null> => {
  const architecture = getPeNativeAotArchitecture(core);
  if (!architecture) return null;
  try {
    const image = createPeNativeAotImage(
      reader,
      core,
      architecture.pointerSize,
      architecture.relocationType
    );
    const sites = indexPeNativeAotPointerSites(relocations, image);
    return sites ? await findNativeAotMetadata(image, sites) : null;
  } catch {
    // A relocation site is only a candidate; malformed/truncated candidates are expected.
  }
  return null;
};
