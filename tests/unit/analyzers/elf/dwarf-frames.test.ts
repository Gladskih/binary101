import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfFrames } from "../../../../analyzers/dwarf/frames.js";
import { elfDwarfFrames } from "../../../../analyzers/elf/dwarf-frames.js";
import { createDwarfFrameBytes } from "../../../fixtures/dwarf-frame-fixture.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";

void test("ELF unwind reuses decoded debug-frame instructions", async () => {
  const source = dwarfMacroSources([{ name: ".debug_frame", bytes: createDwarfFrameBytes() }]).get(".debug_frame")!;
  const frames = await readDwarfFrames(source, "little", 4, 3, []);

  const section = elfDwarfFrames(frames, 7);

  assert.equal(section.sectionIndex, 7);
  assert.equal(section.cies[0]?.instructions, frames.cies[0]?.instructions);
  assert.equal(section.fdes[0]?.instructions, frames.fdes[0]?.instructions);
  assert.deepEqual(section.fdes[0]?.start, { address: 4096n, indirect: false });
  assert.deepEqual(section.issues, []);
  frames.cies[0]!.encoding = null;
  frames.fdes[0]!.segment = 7n;
  assert.deepEqual(elfDwarfFrames(frames, 7).cies, []);
  assert.deepEqual(elfDwarfFrames(frames, 7).fdes, []);
  frames.fdes[0]!.segment = 0n;
  assert.equal(elfDwarfFrames(frames, 7).fdes.length, 1);
});
