import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import type { ParseForUiResult } from "../../../analyzers/index.js";
import type { PeEntrypointDisassemblyController } from "../../../ui/pe-entrypoint-disassembly.js";
import { handlePeSpecialInstructionClick } from "../../../ui/pe-special-instructions.js";
import { FakeHTMLElement, installFakeDom } from "../../helpers/fake-dom.js";
import { MockFile } from "../../helpers/mock-file.js";

class SpecialButton extends FakeHTMLElement {
  dataset: Record<string, string> = { peSpecialRva: "4096" };
  closest(selector: string): SpecialButton | null {
    return selector === "[data-pe-special-rva]" ? this : null;
  }
}

let restoreDom: () => void;
beforeEach(() => { restoreDom = installFakeDom().restore; });
afterEach(() => { restoreDom(); });

const createSubject = () => {
  const file = new MockFile(new Uint8Array(), "special.exe");
  const result = {
    analyzer: "pe", parsed: {
      opt: { Magic: 0x20b }, disassembly: {
        specialInstructions: [
          { categories: ["trap"], instruction: "INT3", count: 1, sampleRvas: [4112] },
          { categories: ["timing"], instruction: "RDTSC", count: 1, sampleRvas: [4096] }
        ]
      }
    }
  } as unknown as ParseForUiResult;
  const calls: unknown[][] = [];
  const controller: Pick<PeEntrypointDisassemblyController, "start"> = {
    start: (...args) => { calls.push(args); }
  };
  return { file, result, calls, controller, button: new SpecialButton() };
};

void test("starts disassembly only at an address from the current ISA findings", () => {
  const subject = createSubject();
  assert.equal(handlePeSpecialInstructionClick(subject.button as unknown as Element,
    subject.file, subject.result, subject.controller), true);
  assert.deepEqual(subject.calls, [[subject.file, subject.result.parsed, 4096]]);
});

for (const value of ["4097", "-1", "4294967296", "NaN", "Infinity", ""]) {
  void test(`rejects an unrecorded or malformed address ${value}`, () => {
    const subject = createSubject();
    subject.button.dataset["peSpecialRva"] = value;
    assert.equal(handlePeSpecialInstructionClick(subject.button as unknown as Element,
      subject.file, subject.result, subject.controller), true);
    assert.deepEqual(subject.calls, []);
  });
}

void test("ignores unrelated targets and absent files", () => {
  const subject = createSubject();
  assert.equal(handlePeSpecialInstructionClick(null,
    subject.file, subject.result, subject.controller), false);
  assert.equal(handlePeSpecialInstructionClick(subject.button as unknown as Element,
    null, subject.result, subject.controller), true);
  assert.deepEqual(subject.calls, []);
});

for (const result of [
  { analyzer: "elf", parsed: {} }, { analyzer: "pe", parsed: null },
  { analyzer: "pe", parsed: { opt: { Magic: 0x107 } } },
  { analyzer: "pe", parsed: { opt: { Magic: 0x20b } } }
]) {
  void test(`ignores a stale action for ${JSON.stringify(result)}`, () => {
    const subject = createSubject();
    assert.equal(handlePeSpecialInstructionClick(subject.button as unknown as Element,
      subject.file, result as unknown as ParseForUiResult, subject.controller), true);
    assert.deepEqual(subject.calls, []);
  });
}
