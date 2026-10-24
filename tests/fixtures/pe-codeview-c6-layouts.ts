import { c6Index, c6Name, c6Sections, c6Type, createC6CodeView } from "./pe-codeview-c6.js";
import { createPeWithDebugPayloads } from "./pe-debug-file.js";

export const createPeWithC6Layouts = () => {
  const sections = c6Sections();
  sections[2]!.data = Uint8Array.from([
    ...c6Type(120, [64, ...c6Index()]), ...c6Type(120, [64, ...c6Index(513)]),
    ...c6Type(120, [64, ...c6Index(512), ...c6Index(513), ...c6Name("<Array>&amp;")]),
    ...c6Type(121, [32, 1, ...c6Index(514), ...c6Index(515), ...c6Name("Packet"), 104]),
    ...c6Type(123, [64, 125, ...c6Name("Range"), 125, 139, 0, 0, 0, 0, 0, 0, 0, 128,
      135, 255, 255, 255, 255, 255, 255, 255, 255]),
    ...c6Type(92, [5, 125, 17])
  ]);
  return createPeWithDebugPayloads([{ type: 2, data: createC6CodeView(sections) }]);
};
