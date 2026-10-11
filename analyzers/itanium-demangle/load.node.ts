import { createDemangler } from "llvm-itanium-demangle";

export const loadItaniumDemangler = async () => createDemangler();
