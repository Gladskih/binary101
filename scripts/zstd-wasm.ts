import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { normalizePath, type Plugin, type ResolvedConfig } from "vite";

// This deliberately checks the pinned zstddec 0.3.1 browser/Node initializer.
// An incompatible dependency update must fail the build rather than restore data: fetches.
// https://github.com/donmccurdy/zstddec-wasm/blob/v0.3.1/src/zstddec.ts
export const externalizeZstdWasm = (source: string, assetUrl: string) => {
  const declarations = [...source.matchAll(/const wasm = "([A-Za-z0-9+/]+={0,2})";/g)];
  if (declarations.length !== 1) throw new Error("Expected one embedded zstddec WASM payload");
  const encoded = declarations[0]![1]!;
  const wasm = Uint8Array.from(Buffer.from(encoded, "base64"));
  if (Buffer.from(wasm).toString("base64") !== encoded || !WebAssembly.validate(wasm)) {
    throw new Error("Invalid embedded zstddec WASM");
  }
  const initializer = /if \(typeof fetch !== "undefined"\) init = fetch\(`data:application\/wasm;base64,\$\{wasm\}`\)([^;]+);\s*else init = WebAssembly.instantiate\(Buffer.from\(wasm, "base64"\), IMPORT_OBJECT\).then\(this._init\);/g;
  const initializers = [...source.matchAll(initializer)];
  if (initializers.length !== 1) throw new Error("Unsupported zstddec initializer");
  return { wasm, code: source
    .replace(declarations[0]![0], () => `import wasmUrl from ${JSON.stringify(assetUrl)};`)
    .replace(initializer, () => `init = fetch(wasmUrl)${initializers[0]![1]};`) };
};

// Vite handles ?url&no-inline assets in both dev and production, including relative base URLs.
// https://vite.dev/guide/assets.html#explicit-url-imports
export const zstdWasmAsset = () => {
  const entry = normalizePath(fileURLToPath(import.meta.resolve("zstddec")));
  let code: string | null = null;
  return {
    name: "zstd-wasm-asset",
    enforce: "pre",
    config: () => ({ optimizeDeps: { exclude: ["zstddec"] } }),
    configResolved(this: void, config: ResolvedConfig) {
      const assetPath = resolve(config.cacheDir, "zstddec.wasm");
      const transformed = externalizeZstdWasm(readFileSync(entry, "utf8"),
        normalizePath(assetPath) + "?url&no-inline");
      mkdirSync(config.cacheDir, { recursive: true });
      writeFileSync(assetPath, transformed.wasm);
      code = transformed.code;
    },
    load(id: string) {
      return normalizePath(id.split("?")[0]!) === entry ? code : null;
    }
  } satisfies Plugin;
};
