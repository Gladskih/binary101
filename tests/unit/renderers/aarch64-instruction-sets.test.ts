import assert from "node:assert/strict";
import { test } from "node:test";
import { DOMParser } from "@xmldom/xmldom";
import { featureDefinitions, type FeatureRequirements } from "llvm-aarch64-disasm";
import { recordAarch64Requirements } from "../../../analyzers/aarch64/instruction-set-usage.js";
import type { ElfInstructionSetUsage } from "../../../analyzers/elf/disassembly-types.js";
import { renderAarch64RequirementTable } from "../../../renderers/aarch64-instruction-sets.js";

const renderPredicates = (predicates: FeatureRequirements["predicates"]): string => {
  const usage = new Map<string, ElfInstructionSetUsage>();
  recordAarch64Requirements({ source: "llvm-tablegen", scope: "opcode", known: true,
    predicates, nonAssemblerPredicates: [] }, usage);
  return renderAarch64RequirementTable([...usage.values()]);
};

const tableRows = (html: string) => Array.from(new DOMParser({
  onError: (_level, message) => assert.fail(message)
}).parseFromString(`<section>${html}</section>`, "text/html").getElementsByTagName("tr"));

// Exercise every feature in the actual decoder metadata, including those outside the old selection.
for (const id of Object.keys(featureDefinitions)) {
  void test(`AArch64 describes detected LLVM feature ${id}`, () => {
    const rows = tableRows(renderPredicates([{ name: "metadata", expression: { feature: id } }]));

    assert.equal(rows.length, 2);
    assert.ok(rows[1]!.getElementsByTagName("td")[3]!.textContent!.trim().length > 0);
    assert.doesNotMatch(rows[1]!.textContent!, /No description available|Reference extensions/);
  });
}

void test("pending and empty AArch64 results contain no table or reference extensions", () => {
  assert.equal(renderAarch64RequirementTable(), "");
  assert.equal(renderAarch64RequirementTable([]), "");
});

void test("detected AArch64 table has descriptions without adding other extensions", () => {
  const html = renderPredicates([{ name: "HasNEON", expression: { feature: "FeatureNEON" } }]);

  assert.ok(html.includes("Streaming SVE mode"));
  assert.ok(html.includes("What it is"));
  assert.ok(html.includes("FEAT_AdvSIMD"));
  assert.ok(html.includes("Advanced SIMD instructions"));
  assert.ok(!html.includes("Scalable Matrix Extension"));
  assert.ok(!html.includes("Reference extensions"));
  assert.ok(!html.includes(">0</td>"));
  assert.equal((html.match(/<tr[ >]/g) ?? []).length, 2);
  assert.deepEqual(tableRows(html).slice(1).map(row => row.firstChild?.textContent), [
    "FEAT_AdvSIMD"
  ]);
  assert.deepEqual(Array.from(tableRows(html)[0]!.childNodes).map(cell => cell.textContent),
    ["Requirement", "Instr.", "Streaming SVE mode", "What it is"]);
  assert.match(html, /Descriptions explain the referenced extensions, not additional requirements/);
  assert.match(html, /unclassified gates do not imply compatibility/);
  assert.doesNotMatch(html, /Hover|title=/);
});

// LLVM 21.1.8 AArch64InstrInfo.td: these gates have the same FeatureNEON expression.
// https://github.com/llvm/llvm-project/blob/llvmorg-21.1.8/llvm/lib/Target/AArch64/AArch64InstrInfo.td
void test("NEON predicate variants retain separate counts and streaming information", () => {
  const usage = new Map<string, ElfInstructionSetUsage>();
  const base: FeatureRequirements = { source: "llvm-tablegen", scope: "opcode", known: true,
    predicates: [{ name: "HasNEON", expression: { feature: "FeatureNEON" } }],
    nonAssemblerPredicates: [] };
  recordAarch64Requirements(base, usage);
  recordAarch64Requirements(base, usage);
  recordAarch64Requirements({ ...base, predicates: [{ name: "HasNEONandIsStreamingSafe",
    expression: { feature: "FeatureNEON" } }] }, usage);

  const html = renderAarch64RequirementTable([...usage.values()]);
  assert.equal((html.match(/>FEAT_AdvSIMD</g) ?? []).length, 2);
  assert.ok(html.includes("Not guaranteed"));
  assert.ok(html.includes("Allowed in either mode"));
  assert.ok(!html.includes("HasNEONandIsStreamingSafe"));
  assert.ok(html.includes('<td class="isaTable__count">2</td>'));
  assert.ok(html.includes('<td class="isaTable__count">1</td>'));
  assert.deepEqual(Array.from(tableRows(html)[1]!.childNodes).map(cell => cell.textContent),
    ["FEAT_AdvSIMD", "2", "Not guaranteed", "Advanced SIMD instructions"]);
  assert.equal(tableRows(html)[2]!.firstChild?.nodeType, 1);
  assert.equal(tableRows(html)[2]!.getElementsByTagName("td")[0]!.hasAttribute("title"), false);
});

void test("conditional streaming compatibility and unclassified gates remain explicit", () => {
  assert.ok(renderPredicates([{ name: "HasNEONandIsSME2p2StreamingSafe",
    expression: { feature: "FeatureNEON" } }]).includes("Requires SME2.2 in streaming mode"));
  assert.ok(renderPredicates([{ name: "UnrecognizedStreamingSafe",
    expression: { feature: "FeatureNEON" } }]).includes("Not classified"));
  assert.ok(renderPredicates([{ name: "HasNEONandIsStreamingSafe",
    expression: { feature: "FeatureNEON" } }, { name: "unknown", expression: true }])
    .includes("Not classified"));
});

void test("nested alternatives and negation keep their gate and describe each referenced feature", () => {
  const html = renderPredicates([{ name: "<predicate>", expression: { all_of: [
    { any_of: [{ feature: "FeatureSVE" }, { feature: "FeatureSME" }] },
    { not: { feature: "<unknown>" } }, false
  ] } }]);

  assert.ok(html.includes("((FEAT_SVE or FEAT_SME) and not (&lt;unknown>) and false)"));
  assert.ok(html.includes("FEAT_SVE: Scalable Vector Extension"));
  assert.ok(html.includes("FEAT_SME: Scalable Matrix Extension"));
  assert.ok(html.includes("No description available"));
  assert.ok(!html.includes("&lt;predicate>"));
  assert.ok(!html.includes("<unknown>"));
  assert.ok(!html.includes(">FEAT_SVE</td>"));
});

void test("empty and older reports retain fallback descriptions and escape content", () => {
  assert.ok(renderPredicates([]).includes("No recorded LLVM feature gate"));
  assert.ok(renderAarch64RequirementTable([{ id: "unknown", label: "<unknown>",
    description: "<description>", instructionCount: 1 }]).includes("&lt;description>"));
  assert.equal(tableRows(renderPredicates([]))[1]!.getElementsByTagName("td")[0]!
    .hasAttribute("title"), false);
  assert.equal(tableRows(renderPredicates([{ name: "constant", expression: true }]))[1]!
    .getElementsByTagName("td")[3]!.textContent,
  "LLVM opcode assembler gates; grouped Arm labels are preserved.");
});
