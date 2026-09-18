import assert from "node:assert/strict";
import { test } from "node:test";
import { enhanceElfLazySections, refreshElfLazySection } from "../../../ui/elf-lazy-sections.js";
import { createLazySection, FakeRoot, installDom } from "../../fixtures/pe-lazy-section-dom.js";
import { relocationFixture } from "../../fixtures/elf-relocations.js";

const fixture = () => {
  const { body, details, section } = createLazySection("resources");
  const root = new FakeRoot(section);
  const elf = relocationFixture().elf;
  elf.notes = { entries: [], issues: ["original notice"] };
  section.dataset["elfLazySection"] = "notes";
  section.setQuery(":scope > details", details);
  section.setQuery(".peSectionBody", body);
  root.querySelectorAll = selector => selector === "[data-elf-lazy-section]" ? [section] : [];
  let toggle: ((event: Event) => void) | undefined;
  details.addEventListener = (_type, handler) => { toggle = handler as typeof toggle; };
  const dom = installDom(section);
  Object.defineProperty(globalThis.document, "querySelector", { value: () => section });
  return { body, details, section, elf, root: root as unknown as ParentNode, restore: dom.restore,
    toggle: (target = details) => toggle?.({ target } as unknown as Event) };
};

void test("mounts on opening, ignores nested toggles, releases DOM and restores state", () => {
  const view = fixture();
  try {
    enhanceElfLazySections(view.root, null);
    enhanceElfLazySections(view.root, view.elf);
    enhanceElfLazySections(view.root, view.elf);
    assert.equal(view.body.innerHTML, "");
    view.details.open = true;
    view.toggle();
    assert.match(view.body.innerHTML, /original notice/);
    view.body.filterControl!.value = "filter";
    view.body.nestedDetails!.open = true;
    view.toggle(view.body.nestedDetails!);
    assert.equal(view.body.filterControl!.value, "filter");
    view.toggle();
    assert.equal(view.body.filterControl!.value, "filter");
    view.details.open = false;
    view.toggle();
    view.toggle();
    assert.equal(view.body.innerHTML, "");
    assert.equal(view.body.nestedDetails, null);
    view.details.open = true;
    view.toggle();
    assert.equal(view.body.filterControl!.value, "filter");
    assert.equal(view.body.nestedDetails!.open, true);
  } finally { view.restore(); }
});

void test("mounts initially open sections and refreshes open and closed content", () => {
  const view = fixture();
  try {
    assert.equal(refreshElfLazySection("notes", view.elf), false);
    view.details.open = true;
    enhanceElfLazySections(view.root, view.elf);
    assert.match(view.body.innerHTML, /original notice/);
    view.elf.notes!.issues = ["updated notice"];
    assert.equal(refreshElfLazySection("notes", view.elf), true);
    assert.match(view.body.innerHTML, /updated notice/);
    view.details.open = false;
    view.toggle();
    assert.equal(refreshElfLazySection("notes", view.elf), true);
    assert.equal(view.body.innerHTML, "");
    assert.equal(refreshElfLazySection("missing", view.elf), false);
  } finally { view.restore(); }
});
