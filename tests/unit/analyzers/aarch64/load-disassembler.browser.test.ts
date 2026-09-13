/// <reference types="vite/client" />
import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { test } from "node:test";
import { aarch64Code } from "../../../fixtures/aarch64-code.js";

void test("browser loader passes the bundler's local asset URL to the WASM runtime", async () => {
  // Node has no Vite ?url import; emulate only the bundler's URL export.
  const hooks = registerHooks({ resolve(specifier, context, nextResolve) {
    if (specifier !== "llvm-aarch64-disasm/llvm-aarch64.wasm?url") return nextResolve(specifier, context);
    return { shortCircuit: true, url: "data:text/javascript," + encodeURIComponent(
      `export default ${JSON.stringify(import.meta.resolve("llvm-aarch64-disasm/llvm-aarch64.wasm"))}`
    ) };
  } });
  try {
    const { loadAarch64Disassembler } = await import("../../../../analyzers/aarch64/load-disassembler.browser.js");
    const decoder = await loadAarch64Disassembler();
    const instruction = decoder.decode(aarch64Code([0xd65f03c0]).data)[0]; // ret

    assert.equal(instruction?.status, "success");
    assert.ok(instruction && "mnemonic" in instruction && instruction.mnemonic === "ret");
  } finally {
    hooks.deregister();
  }
});
