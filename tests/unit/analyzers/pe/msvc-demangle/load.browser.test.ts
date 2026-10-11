/// <reference types="vite/client" />
import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import test from "node:test";
import { fileURLToPath } from "node:url";

void test("shared browser loader passes the bundled WASM asset URL to LLVM", async () => {
  // Emulate Vite's asset export with a local path understood by the Node package entry.
  // The real same-origin URL and CSP are exercised in pe.msvc-rtti.e2e.spec.ts.
  const hooks = registerHooks({ resolve(specifier, context, nextResolve) {
    if (specifier !== "llvm-msvc-demangle/llvm-msvc-demangle.wasm?url") {
      return nextResolve(specifier, context);
    }
    return { shortCircuit: true, url: "data:text/javascript," + encodeURIComponent(
      `export default ${JSON.stringify(fileURLToPath(
        import.meta.resolve("llvm-msvc-demangle/llvm-msvc-demangle.wasm")
      ))}`
    ) };
  } });
  try {
    const { loadMsvcDemangler } = await import(
      "../../../../../analyzers/pe/msvc-demangle/load.browser.js"
    );

    const demangler = await loadMsvcDemangler();

    assert.equal(demangler.demangleTypeWithText(".?AVWidget@demo@@").text, "class demo::Widget");
  } finally {
    hooks.deregister();
  }
});
