import { createDemangler as createRustDemangler } from "llvm-rust-demangle";
import { createDemangler as createDlangDemangler } from "llvm-dlang-demangle";

export const loadRustDemangler = async () => createRustDemangler();
export const loadDlangDemangler = async () => createDlangDemangler();
