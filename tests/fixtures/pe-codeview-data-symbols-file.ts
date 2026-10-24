import { createPeWithDebugPayloads } from "./pe-debug-file.js";
import { createLegacyCodeView, legacyModule, legacyU32 } from "./pe-legacy-codeview.js";
import { codeViewDataSymbol } from "./pe-codeview-data-symbols.js";

const utf8 = (name: string): number[] => [...new TextEncoder().encode(name), 0];

/** An embedded NB09 PE with C7 globals, a public and a scoped data block. */
export const createPeWithCodeViewDataSymbols = () => {
  const records = [
    codeViewDataSymbol(0x110d, utf8("global_value"), 0, 0x74, 0x123, 1),
    codeViewDataSymbol(0x110e, utf8("published_function"), 3, 0, 0x234, 1),
    codeViewDataSymbol(0x1103, utf8("local_block"), 0, 0, 0x300, 1)
  ].flat();
  const symbols = Uint8Array.from([...legacyU32(1), ...records]);
  return createPeWithDebugPayloads([{ type: 2, data: createLegacyCodeView([
    { type: 0x120, module: 1, data: legacyModule() }, { type: 0x125, module: 1, data: symbols }
  ]) }]);
};
