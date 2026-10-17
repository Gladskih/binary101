import assert from "node:assert/strict";
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
  assert.ok(notices);
  notices.generateBundle.call({ emitFile(asset) {
    assert.equal(asset.type, "asset");
    assets.set(asset.fileName, new TextDecoder().decode(asset.source));
    return asset.fileName;
  } });

  assert.match(assets.get("vendor/llvm-rust-demangle/licenses/LLVM.txt")!, /Apache License/);
  assert.match(assets.get("vendor/llvm-dlang-demangle/licenses/LLVM.txt")!, /Apache License/);
  assert.match(assets.get("vendor/llvm-rust-demangle/THIRD_PARTY_NOTICES.md")!, /LLVM/);
  assert.match(assets.get("vendor/llvm-dlang-demangle/THIRD_PARTY_NOTICES.md")!, /LLVM/);
  // Published packages' LLVM 23.1.3 pin, independently checked against upstream.json.
  assert.equal((JSON.parse(assets.get("vendor/llvm-rust-demangle/upstream.json")!) as
    { llvmCommit: string }).llvmCommit, "0d261d1ca552c95a8f007e061c787ac7132fbcbc");
  assert.equal((JSON.parse(assets.get("vendor/llvm-dlang-demangle/upstream.json")!) as
    { llvmCommit: string }).llvmCommit, "0d261d1ca552c95a8f007e061c787ac7132fbcbc");
});
