import wasmURL from "llvm-aarch64-disasm/llvm-aarch64.wasm?url";
import { createDisassembler } from "llvm-aarch64-disasm";

export const loadAarch64Disassembler = async () => createDisassembler({ wasmURL });
