import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewSegmentMap } from "../../analyzers/pe/debug/legacy-codeview-modules.js";
import type { PeSection } from "../../analyzers/pe/types.js";

export const codeViewAddressSections = (): PeSection[] => [
  { name: { kind: "inline", value: ".text" }, virtualAddress: 0x1000, virtualSize: 256,
    sizeOfRawData: 512, pointerToRawData: 512, characteristics: 0x60000020 },
  { name: { kind: "inline", value: ".code" }, virtualAddress: 0x3000, virtualSize: 256,
    sizeOfRawData: 512, pointerToRawData: 1024, characteristics: 0x60000020 }
];

export const codeViewAddressMap = (): LegacyCodeViewSegmentMap => ({ kind: "segmentMap", logicalCount: 1,
  segments: [{ flags: 0x10d, overlay: 0, group: 0, frame: 2, name: 0xffff, className: 0xffff,
    offset: 32, size: 64 }] });

export const codeViewAddressInfo = (): PeLegacyCodeViewInfo => ({ signature: "NB09",
  directories: [{ flags: 0, subsections: [{ type: 0x12d, module: 0xffff, offset: 8, size: 24,
    data: codeViewAddressMap() }] }] });
