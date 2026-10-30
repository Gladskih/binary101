import { writeFile } from "node:fs/promises";
import { createWasmFile } from "../tests/fixtures/wasm-fixtures.js";

const output = process.argv[2];
if (!output) throw new Error("Usage: npx tsx scripts/buildWasmSample.ts <output.wasm>");
await writeFile(output, new Uint8Array(await createWasmFile().arrayBuffer()));
