"use strict";
import { archiveProbes } from "./magic-archives.js";
import { imageProbes } from "./magic-images.js";
import { mediaProbes } from "./magic-media.js";
import { miscProbes } from "./magic-misc.js";
import type { ProbeResult } from "./probe-types.js";

const MAGIC_PROBES: Array<(dv: DataView) => ProbeResult> = [
  ...archiveProbes,
  ...imageProbes,
  ...mediaProbes,
  ...miscProbes
];

const probeByMagic = (dv: DataView): ProbeResult => {
  for (const probe of MAGIC_PROBES) {
    const label = probe(dv);
    if (label) return label;
  }
  return null;
};

export { MAGIC_PROBES, probeByMagic };
