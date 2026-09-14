import assert from "node:assert/strict";
import { test } from "node:test";
import { updateAarch64InstructionSets } from "../../../ui/aarch64-instruction-sets.js";
import { FakeHTMLElement, installFakeDom } from "../../helpers/fake-dom.js";

class RequirementsContainer extends FakeHTMLElement {
  innerHTML = "previous result";
  querySelectorAll(_selector: string): unknown[] { return []; }
}

class PopulatedRequirementsContainer extends RequirementsContainer {
  countCell = { textContent: "1" };
  override querySelectorAll(selector: string): unknown[] {
    return selector === "tbody tr"
      ? [{ getAttribute: () => "neon", cells: [{}, this.countCell] }] : [];
  }
}

void test("progress changes existing count cells without rebuilding descriptions", () => {
  const container = new PopulatedRequirementsContainer();
  const dom = installFakeDom({ requirements: container });
  try {
    const set = { id: "neon", label: "FEAT_AdvSIMD", description: "Advanced SIMD", instructionCount: 9 };
    updateAarch64InstructionSets("requirements", { stage: "decoding", aarch64InstructionSets: [set] });
    assert.equal(container.countCell.textContent, "9");
    assert.equal(container.innerHTML, "previous result");
    updateAarch64InstructionSets("requirements", { stage: "decoding",
      aarch64InstructionSets: [{ ...set, id: "another" }] });
    assert.match(container.innerHTML, /Advanced SIMD/);
  } finally { dom.restore(); }
});

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
    assert.equal((container.innerHTML.match(/<tr[ >]/g) ?? []).length, 2);
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
