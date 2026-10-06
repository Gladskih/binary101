import { createReadyToRunSeedFixture } from "./ready-to-run-seed-fixture.js";
import { thunkSectionFixture } from "./ready-to-run-thunk-section-fixture.js";

export const thunkImageFixture = () => {
  const fixture = thunkSectionFixture();
  const pe = createReadyToRunSeedFixture().pe;
  pe.clr!.readyToRun!.sections = [fixture.section];
  pe.opt.SizeOfImage = fixture.bytes.length;
  pe.sections[0]!.virtualAddress = fixture.section.rva;
  pe.sections[0]!.pointerToRawData = fixture.section.rva;
  return { ...fixture, pe };
};
