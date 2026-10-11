import { createDemangler } from "llvm-msvc-demangle";

export const loadMsvcRttiDemangler = async () => createDemangler();
