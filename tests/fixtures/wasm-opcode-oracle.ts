import { readFileSync } from "node:fs";

// Independent upstream reference, including its original Apache-2.0 license header:
// https://github.com/WebAssembly/wabt/blob/ed1a832d9553158a2a67bf6c6d98a96207a4ee6b/include/wabt/opcode.def
export const upstreamWasmOpcodes = (prefix: number): Record<number, string> =>
  Object.fromEntries(readFileSync(new URL("./wasm-opcodes.def", import.meta.url), "utf8")
    .split("\n")
    .flatMap(line => {
      const match = /^WABT_OPCODE\([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,\s*(\w+),\s*(\w+),[^,]+,\s*"([^"]+)"/.exec(line);
      if (!match || Number(match[1]) !== prefix) return [];
      const code = Number(match[2]);
      // WABT's 0xe* entries are interpreter-private; atomic GC extensions are not modeled yet.
      if (prefix === 0 && code >= 0xe0) return [];
      if (prefix === 0xfe && code > 0x4e) return [];
      return [[code, match[3]!]];
    }));
