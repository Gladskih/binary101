import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

// TD32 TModuleInfo has a 28-byte header and indexed names, unlike CV4's Pascal strings.
// https://github.com/project-jedi/jcl/blob/10b92737050d9aaa0af17fe099a737d390b6c80e/jcl/source/windows/JclTD32.pas#L215
export const readTd32Module = async (reader: LegacyCodeViewReader) => {
  const header = await reader.view(0, 28);
  const count = header.getUint16(4, true);
  if (count * 12 > reader.size - 28) throw new Error("TD32 module segments are truncated.");
  if ([16, 20, 24].some(offset => header.getUint32(offset, true))) reader.warn("TD32 module reserved fields are nonzero.");
  const segments: { segment: number; flags: number; offset: number; size: number }[] = [];
  for (let index = 0; index < count; index++) {
    const view = await reader.view(28 + index * 12, 12);
    const flags = view.getUint16(2, true);
    if (flags > 1) reader.warn("TD32 module segment has unknown attributes.");
    segments.push({ segment: view.getUint16(0, true), flags,
      offset: view.getUint32(4, true), size: view.getUint32(8, true) });
  }
  return { kind: "module" as const, overlay: header.getUint16(0, true), library: header.getUint16(2, true),
    style: header.getUint16(6, true), nameIndex: header.getUint32(8, true),
    timestamp: header.getUint32(12, true), segments };
};
