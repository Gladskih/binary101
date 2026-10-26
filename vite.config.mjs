import { defineConfig } from "vite";
import { fileURLToPath, URL } from "node:url";
import { readFileSync } from "node:fs";
import { zstdWasmAsset } from "./scripts/zstd-wasm.ts";

export default defineConfig({
  plugins: [zstdWasmAsset(), {
    name: "disassembler-notices",
    generateBundle() {
      for (const [packageName, names] of Object.entries({
        "lzma-sdk-decode": [
          "LICENSE", "THIRD_PARTY_NOTICES.md", "upstream.json", "licenses/LZMA-SDK.txt",
          "licenses/emscripten-LICENSE.txt", "licenses/compiler-rt.txt", "licenses/musl.txt"
        ],
        "llvm-itanium-demangle": [
          "LICENSE", "THIRD_PARTY_NOTICES.md", "licenses/LLVM.txt",
          "licenses/emscripten-AUTHORS.txt", "licenses/emscripten-LICENSE.txt",
          "licenses/libcxx.txt", "licenses/libcxxabi.txt", "licenses/libunwind.txt",
          "licenses/compiler-rt.txt", "licenses/musl.txt", "upstream.json"
        ],
        "llvm-msvc-demangle": [
          "LICENSE", "THIRD_PARTY_NOTICES.md", "licenses/LLVM.txt",
          "licenses/emscripten-AUTHORS.txt", "licenses/emscripten-LICENSE.txt",
          "licenses/libcxx.txt", "licenses/libcxxabi.txt", "licenses/libunwind.txt",
          "licenses/compiler-rt.txt", "licenses/musl.txt", "upstream.json"
        ],
        "llvm-rust-demangle": [
          "LICENSE", "THIRD_PARTY_NOTICES.md", "licenses/LLVM.txt",
          "licenses/emscripten-AUTHORS.txt", "licenses/emscripten-LICENSE.txt",
          "licenses/libcxx.txt", "licenses/libcxxabi.txt", "licenses/libunwind.txt",
          "licenses/compiler-rt.txt", "licenses/musl.txt", "upstream.json"
        ],
        "llvm-dlang-demangle": [
          "LICENSE", "THIRD_PARTY_NOTICES.md", "licenses/LLVM.txt",
          "licenses/emscripten-AUTHORS.txt", "licenses/emscripten-LICENSE.txt",
          "licenses/libcxx.txt", "licenses/libcxxabi.txt", "licenses/libunwind.txt",
          "licenses/compiler-rt.txt", "licenses/musl.txt", "upstream.json"
        ],
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
      "#lzma-decoder-loader": fileURLToPath(
        new URL("./analyzers/lzma/load.browser.ts", import.meta.url)
      ),
      "./windows-trust-store.generated.json": fileURLToPath(
        new URL("./generated/windows-trust-store.generated.json", import.meta.url)
      ),
      "#itanium-demangler-loader": fileURLToPath(
        new URL("./analyzers/itanium-demangle/load.browser.ts", import.meta.url)
      ),
      "#msvc-demangler-loader": fileURLToPath(
        new URL("./analyzers/pe/msvc-demangle/load.browser.ts", import.meta.url)
      ),
      "#rust-dlang-demangler-loader": fileURLToPath(
        new URL("./analyzers/symbol-demangle/load.browser.ts", import.meta.url)
      ),
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
