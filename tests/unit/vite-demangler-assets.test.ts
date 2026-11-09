import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";

type NoticeAsset = { type: string; fileName: string; source: Uint8Array };
type NoticePlugin = {
  name: string;
  generateBundle: (this: { emitFile: (asset: NoticeAsset) => string }) => void;
};

void test("Vite emits local Rust/D loader bindings, upstream pins and license notices", async () => {
  const configuration = await import(pathToFileURL(resolve("vite.config.mjs")).href) as {
    default: { plugins: NoticePlugin[]; resolve: { alias: Record<string, string> } }
  };
  const assets = new Map<string, string>();
  const notices = configuration.default.plugins.find(plugin => plugin.name === "disassembler-notices");

  assert.match(configuration.default.resolve.alias["#rust-dlang-demangler-loader"]!,
    /analyzers[/\\]symbol-demangle[/\\]load\.browser\.ts$/);
  assert.match(configuration.default.resolve.alias["#lzma-decoder-loader"]!,
    /analyzers[/\\]lzma[/\\]load\.browser\.ts$/);
  assert.ok(notices);
  notices.generateBundle.call({ emitFile(asset) {
    assert.equal(asset.type, "asset");
    assets.set(asset.fileName, new TextDecoder().decode(asset.source));
    return asset.fileName;
  } });

  assert.match(assets.get("vendor/llvm-rust-demangle/licenses/LLVM.txt")!, /Apache License/);
  assert.match(assets.get("vendor/lzma-sdk-decode/licenses/LZMA-SDK.txt")!, /ANSI-C LZMA Decoder/);
  assert.match(assets.get("vendor/lzma-sdk-decode/LICENSE")!, /MIT/);
  assert.match(assets.get("vendor/lzma-sdk-decode/THIRD_PARTY_NOTICES.md")!, /Igor Pavlov/);
  assert.equal(assets.get("vendor/lzma-sdk-decode/upstream.json"),
    await readFile(resolve("node_modules/lzma-sdk-decode/upstream.json"), "utf8"));
  assert.match(assets.get("vendor/llvm-dlang-demangle/licenses/LLVM.txt")!, /Apache License/);
  assert.match(assets.get("vendor/llvm-rust-demangle/THIRD_PARTY_NOTICES.md")!, /LLVM/);
  assert.match(assets.get("vendor/llvm-dlang-demangle/THIRD_PARTY_NOTICES.md")!, /LLVM/);
  assert.equal(assets.get("vendor/llvm-rust-demangle/upstream.json"),
    await readFile(resolve("node_modules/llvm-rust-demangle/upstream.json"), "utf8"));
  assert.equal(assets.get("vendor/llvm-dlang-demangle/upstream.json"),
    await readFile(resolve("node_modules/llvm-dlang-demangle/upstream.json"), "utf8"));
});
