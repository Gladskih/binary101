import assert from "node:assert/strict";
import { test } from "node:test";
import {
  renderElfSectionStart, renderElfSectionEnd
} from "../../../../renderers/elf/collapsible-section.js";

void test("renders a closed section with an escaped title and matching containers", () => {
  assert.equal(renderElfSectionStart("<ELF metadata>") + "body" + renderElfSectionEnd(),
    "<section class=\"peSection\"><details class=\"peSectionDetails\">" +
    "<summary class=\"peSectionSummary\"><b>&lt;ELF metadata></b></summary>" +
    "<div class=\"peSectionBody\">body</div></details></section>");
});

void test("accepts an empty title without inserting markup", () => {
  assert.ok(renderElfSectionStart("").includes("<b></b></summary>"));
});
