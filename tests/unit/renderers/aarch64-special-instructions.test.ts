import assert from "node:assert/strict";
import { test } from "node:test";
import { DOMParser } from "@xmldom/xmldom";
import { renderAarch64SpecialInstructions } from "../../../renderers/aarch64-special-instructions.js";

void test("A64 special instructions distinguish privilege, configuration and debug state", () => {
  const html = renderAarch64SpecialInstructions([
    { instruction: "MRS SCTLR_EL1", access: "EL1+", count: 2, sampleAddresses: [0n, 4n] },
    { instruction: "MRS HCR_EL2", access: "EL2+", count: 1, sampleAddresses: [8n] },
    { instruction: "MRS SCR_EL3", access: "EL3", count: 1, sampleAddresses: [12n] },
    { instruction: "MSR DAIFSet", access: "configuration", count: 1, sampleAddresses: [16n] },
    { instruction: "DRPS", access: "debug", count: 1, sampleAddresses: [20n] }
  ], "Example RVAs");

  assert.match(html, /<h4>Special instructions<\/h4>/);
  assert.match(html, /<th>Category<\/th><th>Instruction<\/th>/);
  assert.match(html, /<th>Example RVAs<\/th>/);
  assert.match(html, /Kernel privilege \(EL1\+\)/);
  assert.match(html, /Hypervisor privilege \(EL2\+\)/);
  assert.match(html, /Monitor privilege \(EL3\)/);
  assert.match(html, /Configured EL0 access/);
  assert.match(html, /Halting debug state/);
  assert.match(html, /SCTLR_EL1.UMA/);
  assert.match(html, /administrator rights alone do not suffice/);
  assert.match(html, /<code>0x0<\/code> <code>0x4<\/code>/);
  assert.match(html, /<td style="text-align:right">2<\/td>/);
  assert.match(html, /Counts are decoded instruction sites/);
  assert.match(html, /Up to three addresses/);
  assert.match(html, /Expand a category/);
  assert.match(html, /minimum encoding requirements/);
  assert.match(html, /not proof that an operation exists/);
  assert.match(html, /Unvisited code may contain more sites/);
  assert.match(html, /Instruction reference/);
  assert.match(html, /Requires at least Exception Level 1/);
  assert.match(html, /OS may emulate some trapped accesses/);
  assert.match(html, /Requires at least Exception Level 2/);
  assert.match(html, /Virtualization controls may trap/);
  assert.match(html, /Requires Exception Level 3/);
  assert.match(html, /directly access this facility/);
  assert.match(html, /when disabled, the access traps/);
  assert.match(html, /DRPS and DCPS operate in halting debug state/);
  assert.match(html, /make them ordinary executable instructions/);
  const document = new DOMParser({ onError: (_level, message) => assert.fail(message) })
    .parseFromString(`<div>${html}</div>`, "text/xml");
  assert.equal(document.getElementsByTagName("table").length, 1);
  assert.equal(document.getElementsByTagName("tr").length, 6);
  assert.equal(document.getElementsByTagName("td").length, 20);
  assert.equal(document.getElementsByTagName("tbody")[0]?.childNodes.length, 5);
  assert.equal(document.getElementsByTagName("a")[0]?.getAttribute("href"),
    "https://developer.arm.com/documentation/ddi0487/latest/");
  assert.equal(document.getElementsByTagName("a")[0]?.textContent,
    "Arm Architecture Reference Manual");
  assert.doesNotMatch(html, /Intel|AMD|<button/);
});

void test("A64 special instruction table escapes text and preserves high addresses", () => {
  const html = renderAarch64SpecialInstructions([
    { instruction: "<MRS>", access: "EL1+", count: 1, sampleAddresses: [0xffff800000000004n] },
    { instruction: "SYS", access: "EL1+", count: 1, sampleAddresses: [] }
  ], "<addresses>");

  assert.match(html, /&lt;MRS>/);
  assert.match(html, /&lt;addresses>/);
  assert.match(html, /0xffff800000000004/);
  assert.match(html, /Unavailable/);
  assert.doesNotMatch(html, /<MRS>|<addresses>/);
});

void test("A64 empty findings explain the sampling limit without an empty table", () => {
  const html = renderAarch64SpecialInstructions([], "Example RVAs");

  assert.match(html, /None detected in the sampled code/);
  assert.doesNotMatch(html, /<table/);
});
