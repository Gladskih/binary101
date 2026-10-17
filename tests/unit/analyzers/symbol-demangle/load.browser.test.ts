/// <reference types="vite/client" />
import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { test } from "node:test";

void test("browser loaders use their respective packaged local WASM URLs", async () => {
  const hooks = registerHooks({ resolve(specifier, context, nextResolve) {
    if (specifier === "llvm-rust-demangle" || specifier === "llvm-dlang-demangle") {
      return { shortCircuit: true, url: "data:text/javascript," + encodeURIComponent(
        "export const createDemangler = configuration => ({ " +
        "demangleWithText: () => ({ text: configuration?.wasmURL }) });"
      ) };
    }
    if (!/^llvm-(rust|dlang)-demangle\/llvm-(rust|dlang)-demangle\.wasm\?url$/.test(specifier)) {
      return nextResolve(specifier, context);
    }
    return { shortCircuit: true, url: "data:text/javascript," + encodeURIComponent(
      `export default ${JSON.stringify("/local-assets/" + specifier.split("/")[1]!.slice(0, -4))}`
    ) };
  } });
  try {
    const { loadRustDemangler, loadDlangDemangler } = await import(
      "../../../../analyzers/symbol-demangle/load.browser.js"
    );

    assert.equal((await loadRustDemangler()).demangleWithText("_RC1a").text,
      "/local-assets/llvm-rust-demangle.wasm");
    assert.equal((await loadDlangDemangler()).demangleWithText("_Dmain").text,
      "/local-assets/llvm-dlang-demangle.wasm");
  } finally {
    hooks.deregister();
  }
});
