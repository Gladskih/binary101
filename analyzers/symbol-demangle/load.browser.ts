import rustWasmURL from "llvm-rust-demangle/llvm-rust-demangle.wasm?url";
import dlangWasmURL from "llvm-dlang-demangle/llvm-dlang-demangle.wasm?url";

export const loadRustDemangler = async () => {
  const { createDemangler } = await import("llvm-rust-demangle");
  return createDemangler({ wasmURL: rustWasmURL });
};

export const loadDlangDemangler = async () => {
  const { createDemangler } = await import("llvm-dlang-demangle");
  return createDemangler({ wasmURL: dlangWasmURL });
};
