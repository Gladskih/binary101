import { defineConfig } from "vite";
import { fileURLToPath, URL } from "node:url";
import { readFileSync } from "node:fs";

export default defineConfig({
  plugins: [{
    name: "disassembler-notices",
    generateBundle() {
      for (const [packageName, names] of Object.entries({
        "llvm-aarch64-disasm": [
          "LICENSE", "THIRD_PARTY_NOTICES.md", "upstream.json", "licenses/LLVM.txt",
          "licenses/compiler-rt.txt", "licenses/emscripten-AUTHORS.txt",
          "licenses/emscripten-LICENSE.txt", "licenses/libcxx.txt", "licenses/musl.txt"
        ],
        "iced-x86-disasm": [
          "LICENSE", "THIRD_PARTY_NOTICES.md", "upstream.json", "licenses/iced.txt",
          "licenses/wasm-bindgen-MIT.txt"
        ]
      })) {
        for (const name of names) {
          this.emitFile({
            type: "asset",
            fileName: `vendor/${packageName}/${name}`,
            source: readFileSync(new URL(`./node_modules/${packageName}/${name}`, import.meta.url))
          });
        }
      }
    }
  }],
  base: "./",
  resolve: {
    alias: {
      "#aarch64-disassembler-loader": fileURLToPath(
        new URL("./analyzers/aarch64/load-disassembler.browser.ts", import.meta.url)
      )
    }
  },
  optimizeDeps: {
    entries: ["index.html"]
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
