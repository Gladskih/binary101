import { createDemangler } from "llvm-msvc-demangle";

export const loadMsvcDemangler = async () => createDemangler();
