import { defineConfig } from "vite";
import { fileURLToPath, URL } from "node:url";
import { readFileSync } from "node:fs";

export default defineConfig({
  plugins: [{
    name: "llvm-aarch64-notices",
    generateBundle() {
      for (const name of ["LICENSE", "THIRD_PARTY_NOTICES.md", "upstream.json",
        "licenses/LLVM.txt", "licenses/compiler-rt.txt", "licenses/emscripten-AUTHORS.txt",
        "licenses/emscripten-LICENSE.txt", "licenses/libcxx.txt", "licenses/musl.txt"]) {
        this.emitFile({
          type: "asset",
          fileName: `vendor/llvm-aarch64-disasm/${name}`,
          source: readFileSync(new URL(`./node_modules/llvm-aarch64-disasm/${name}`, import.meta.url))
        });
      }
    }
  }],
  base: "./",
  resolve: {
    alias: {
      "#aarch64-disassembler-loader": fileURLToPath(
        new URL("./analyzers/aarch64/load-disassembler.browser.ts", import.meta.url)
      ),
      "#iced-x86-loader": fileURLToPath(
        new URL("./analyzers/x86/load-iced-x86.browser.ts", import.meta.url)
      )
    }
  },
  build: {
    target: "esnext"
  },
  preview: {
    host: "127.0.0.1",
    port: 4173,
    strictPort: true
  }
});
