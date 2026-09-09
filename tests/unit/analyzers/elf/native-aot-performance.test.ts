import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { analyzeElfNativeAot } from "../../../../analyzers/elf/native-aot.js";
import { createElfNativeAotFixture } from "../../../helpers/elf-native-aot-fixture.js";
import { MockFile } from "../../../helpers/mock-file.js";
void test("NativeAOT candidate reads reuse windows across interleaved relocation targets", async () => {
  const fixture = createElfNativeAotFixture();
  const parsed = await parseElf(fixture.file);
  assert.ok(parsed?.relocations?.entries[0]);
  // Exceed the range reader's 16-window cache with 32 distant target regions.
  const regionBytes = 128 * 1024;
  const bytes = new Uint8Array(33 * regionBytes);
  const file = new MockFile(bytes, "interleaved-targets.elf", "application/x-elf");
  const slice = file.slice.bind(file);
  let reads = 0;
  file.slice = (start, end) => {
    reads += 1;
    return slice(start, end);
  };
  const elf = { ...parsed, programHeaders: [{ ...parsed.programHeaders[0]!,
    offset: 0n, vaddr: 0n, filesz: BigInt(bytes.length), memsz: BigInt(bytes.length)
  }] };
  const relocations = { ...parsed.relocations, entries: Array.from({ length: 96 }, (_, index) => ({
    ...parsed.relocations!.entries[0]!, offset: BigInt(index * 8),
    addend: BigInt((index % 32 + 1) * regionBytes + Math.floor(index / 32) * 8)
  })) };
  const issues: string[] = [];

  assert.equal(await analyzeElfNativeAot(file, elf, issues, relocations), null);

  assert.deepEqual(issues, []);
  assert.ok(reads <= 32, `Expected at most one read per region, got ${reads}`);
});
