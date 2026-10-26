/// <reference types="vite/client" />
import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { test } from "node:test";

void test("browser initializes the SDK with Vite's same-origin WASM asset", async () => {
  const hooks = registerHooks({ resolve(specifier, context, nextResolve) {
    if (specifier === "lzma-sdk-decode/lzma-sdk-decode.wasm?url") {
      return { shortCircuit: true, url: "data:text/javascript," + encodeURIComponent(
        'export default "/assets/lzma-sdk-decode.wasm";') };
    }
    if (specifier === "lzma-sdk-decode") {
      return { shortCircuit: true, url: "data:text/javascript," + encodeURIComponent(
        "export const createDecoder = options => options;") };
    }
    return nextResolve(specifier, context);
  } });
  try {
    const { loadLzmaDecoder } = await import("../../../../analyzers/lzma/load.browser.js");

    assert.deepEqual(await loadLzmaDecoder(), { wasmURL: "/assets/lzma-sdk-decode.wasm" });
  } finally {
    hooks.deregister();
  }
});
