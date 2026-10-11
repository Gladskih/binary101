/// <reference types="vite/client" />
import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

void test("browser loader forwards the bundled Itanium WASM asset URL", async () => {
  const hooks = registerHooks({ resolve(specifier, context, nextResolve) {
    if (specifier !== "llvm-itanium-demangle/llvm-itanium-demangle.wasm?url") {
      return nextResolve(specifier, context);
    }
    return { shortCircuit: true, url: "data:text/javascript," + encodeURIComponent(
      `export default ${JSON.stringify(fileURLToPath(
        import.meta.resolve("llvm-itanium-demangle/llvm-itanium-demangle.wasm")
      ))}`
    ) };
  } });
  try {
    const { loadItaniumDemangler } = await import(
      "../../../../analyzers/itanium-demangle/load.browser.js"
    );
    const api = await loadItaniumDemangler();

    assert.equal(api.demangleWithText("_Z1fi").text, "f(int)");
  } finally {
    hooks.deregister();
  }
});
