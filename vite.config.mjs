import { defineConfig } from "vite";
import { fileURLToPath, URL } from "node:url";

export default defineConfig({
  base: "./",
  resolve: {
    alias: {
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
