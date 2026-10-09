import assert from "node:assert/strict";
import { mkdtempDisposableSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { normalizePath, type ResolvedConfig } from "vite";
import { externalizeZstdWasm, zstdWasmAsset } from "../../../scripts/zstd-wasm.js";

const upstream = readFileSync(new URL("../../../node_modules/zstddec/dist/zstddec.mjs", import.meta.url), "utf8");

void test("zstddec build transformation extracts its actual WASM without retaining base64", () => {
  const transformed = externalizeZstdWasm(upstream, "/assets/decoder.wasm?url&no-inline");
  assert.equal(WebAssembly.validate(transformed.wasm), true);
  assert.match(transformed.code, /import wasmUrl from "\/assets\/decoder.wasm\?url&no-inline"/);
  assert.match(transformed.code, /init = fetch\(wasmUrl\)/);
  assert.doesNotMatch(transformed.code, /data:application\/wasm|Buffer\.from|const wasm =/);
  assert.match(transformed.code, /class/);
  assert.match(transformed.code, /BSD License/);
  assert.ok(transformed.code.length < upstream.length - transformed.wasm.length);
});

void test("zstddec build transformation rejects an incompatible upstream initializer", () => {
  assert.throws(() => externalizeZstdWasm(upstream.replace("typeof fetch", "typeof request"), "decoder.wasm"),
    /Unsupported zstddec initializer/);
  assert.throws(() => externalizeZstdWasm(upstream.replace(
    /if \(typeof fetch[\s\S]+?else init = [^;]+;/, "$&\n$&"), "decoder.wasm"),
    /Unsupported zstddec initializer/);
});

void test("zstddec build transformation rejects missing and duplicate payload declarations", () => {
  assert.throws(() => externalizeZstdWasm(upstream.replace("const wasm =", "const binary ="), "decoder.wasm"),
    /Expected one embedded zstddec WASM payload/);
  assert.throws(() => externalizeZstdWasm(upstream + "\nconst wasm = \"AA==\";", "decoder.wasm"),
    /Expected one embedded zstddec WASM payload/);
});

void test("zstddec build transformation rejects malformed WASM and noncanonical base64", () => {
  // AA== is one zero byte. The second payload is an otherwise valid empty WASM module
  // with nonzero base64 padding bits (B instead of A immediately before '=').
  // https://webassembly.github.io/spec/core/binary/modules.html#binary-module
  assert.throws(() => externalizeZstdWasm(upstream.replace(/const wasm = "[^"]+";/,
    "const wasm = \"AA==\";"), "decoder.wasm"), /Invalid embedded zstddec WASM/);
  assert.throws(() => externalizeZstdWasm(upstream.replace(/const wasm = "[^"]+";/,
    "const wasm = \"AGFzbQEAAAB=\";"), "decoder.wasm"), /Invalid embedded zstddec WASM/);
});

const withWasmCache = (check: (directory: string) => void): void => {
  const directory = mkdtempDisposableSync(join(tmpdir(), "binary101-zstd-"));
  try {
    check(directory.path);
  } finally {
    assert.equal(dirname(directory.path), resolve(tmpdir()));
    assert.ok(basename(directory.path).startsWith("binary101-zstd-"));
    directory.remove();
  }
};

void test("Vite plugin externalizes only the package entry and excludes it from dependency prebundling", () => {
  withWasmCache(directory => {
    const plugin = zstdWasmAsset();
    assert.ok(plugin.name.length > 0);
    assert.deepEqual(plugin.config(), { optimizeDeps: { exclude: ["zstddec"] } });
    const cacheDir = join(directory, "nested", "cache");
    plugin.configResolved({ cacheDir } as ResolvedConfig);
    plugin.configResolved({ cacheDir } as ResolvedConfig);
    const entry = fileURLToPath(import.meta.resolve("zstddec"));
    assert.equal(WebAssembly.validate(readFileSync(join(cacheDir, "zstddec.wasm"))), true);
    assert.equal(plugin.load(entry), plugin.load(normalizePath(entry) + "?v=test"));
    assert.match(plugin.load(entry)!, /fetch\(wasmUrl\)/);
    assert.ok(plugin.load(entry)!.includes(JSON.stringify(normalizePath(join(cacheDir,
      "zstddec.wasm")) + "?url&no-inline")));
    assert.doesNotMatch(plugin.load(entry)!, /data:application\/wasm/);
    assert.equal(plugin.load(entry + ".other"), null);
  });
});

void test("Vite plugin stops when its generated asset cannot be written", () => {
  withWasmCache(directory => {
    const cacheDir = join(directory, "blocked-cache");
    writeFileSync(cacheDir, "a regular file cannot contain generated WASM");
    assert.throws(() => zstdWasmAsset().configResolved({ cacheDir } as ResolvedConfig), /EEXIST/);
  });
});
