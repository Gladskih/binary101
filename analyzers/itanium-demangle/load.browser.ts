import wasmURL from "llvm-itanium-demangle/llvm-itanium-demangle.wasm?url";

export const loadItaniumDemangler = async () => {
  const { createDemangler } = await import("llvm-itanium-demangle");
  return createDemangler({ wasmURL });
};
