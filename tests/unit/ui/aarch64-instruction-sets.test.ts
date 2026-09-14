import assert from "node:assert/strict";
import { test } from "node:test";
import { updateAarch64InstructionSets } from "../../../ui/aarch64-instruction-sets.js";
import { FakeHTMLElement, installFakeDom } from "../../helpers/fake-dom.js";

class RequirementsContainer extends FakeHTMLElement {
  innerHTML = "previous result";
  querySelectorAll(): never[] { return []; }
}

void test("AArch64 progress clears old rows and replaces counts without duplicating rows", () => {
  const container = new RequirementsContainer();
  const dom = installFakeDom({ requirements: container });
  try {
    updateAarch64InstructionSets("requirements", { stage: "loading" });
    assert.equal(container.innerHTML, "");
    const set = { id: "neon", label: "FEAT_AdvSIMD", description: "Advanced SIMD",
      instructionCount: 1 };
    updateAarch64InstructionSets("requirements", { stage: "decoding", aarch64InstructionSets: [set] });
    assert.match(container.innerHTML, /FEAT_AdvSIMD/);
    assert.match(container.innerHTML, /isaTable__count">1</);
    updateAarch64InstructionSets("requirements", { stage: "decoding",
      aarch64InstructionSets: [{ ...set, instructionCount: 2 }] });
    assert.match(container.innerHTML, /isaTable__count">2</);
    assert.equal((container.innerHTML.match(/<tr>/g) ?? []).length, 2);
    updateAarch64InstructionSets("requirements", { stage: "done", aarch64InstructionSets: [] });
    assert.equal(container.innerHTML, "");
  } finally { dom.restore(); }
});

void test("missing panels and progress without AArch64 data leave the UI alone", () => {
  const container = new RequirementsContainer();
  const dom = installFakeDom({ requirements: container });
  try {
    updateAarch64InstructionSets("missing", { stage: "decoding", aarch64InstructionSets: [] });
    updateAarch64InstructionSets("requirements", { stage: "decoding" });
    assert.equal(container.innerHTML, "previous result");
  } finally { dom.restore(); }
});
