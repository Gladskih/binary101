import { DfmReader, readDfmValue } from "./dfm-values.js";
import type { DfmProperty } from "./dfm-values.js";
import type { ResourcePreviewResult } from "./types.js";

export interface DfmComponent {
  className: string;
  name: string;
  flags: number;
  childPosition?: string;
  properties: DfmProperty[];
  children: DfmComponent[];
}

const componentHeader = (reader: DfmReader): DfmComponent => {
  const flags = (reader.peek() & 0xf0) === 0xf0 ? reader.byte() & 0x0f : 0;
  if (flags & 8) throw new Error("DFM component has unsupported prefix flags.");
  if ((flags & 2) && ![2, 3, 4].includes(reader.peek())) {
    throw new Error("DFM child position is not an integer.");
  }
  const position = flags & 2 ? readDfmValue(reader) : null;
  const className = reader.shortString();
  const name = reader.shortString();
  if (!className) throw new Error("DFM component class is empty.");
  return { className, name, flags,
    ...(position?.kind === "number" ? { childPosition: position.value } : {}), properties: [], children: [] };
};

const readComponents = (reader: DfmReader, root: DfmComponent): void => {
    const stack = [{ node: root, phase: "properties" }];
    while (stack.length) {
      const frame = stack[stack.length - 1]!;
      if (frame.phase === "properties") {
        const name = reader.shortString();
        if (!name) frame.phase = "children";
        else frame.node.properties.push({ name, value: readDfmValue(reader) });
      } else if (reader.peek() === 0) { reader.byte(); stack.pop(); }
      else {
        const child = componentHeader(reader);
        frame.node.children.push(child); stack.push({ node: child, phase: "properties" });
      }
    }
};

export const addDfmPreview = (data: Uint8Array): ResourcePreviewResult | null => {
  // FilerSignature TPF0. A mere class/form name is insufficient to claim a binary DFM.
  if (new TextDecoder("ascii").decode(data.subarray(0, 4)) !== "TPF0") return null;
  const reader = new DfmReader(data);
  const issues: string[] = [];
  let root: DfmComponent | undefined;
  try {
    root = componentHeader(reader);
    readComponents(reader, root);
    if (reader.offset < data.length) issues.push("DFM contains bytes after the root component.");
  } catch (error) { issues.push(error instanceof Error ? error.message : String(error)); }
  return { preview: { previewKind: "dfm", ...(root ? { dfm: root } : {}), previewFields: [
    { label: "Format", value: "Delphi/FPC binary form (TPF0)" },
    { label: "ANSI strings", value: "Windows-1252 approximation; stream has no code page." }
  ] }, ...(issues.length ? { issues } : {}) };
};
