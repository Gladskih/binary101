import wasmURL from "llvm-msvc-demangle/llvm-msvc-demangle.wasm?url";

export const loadMsvcDemangler = async () => {
  const { createDemangler } = await import("llvm-msvc-demangle");
  return createDemangler({ wasmURL });
};
