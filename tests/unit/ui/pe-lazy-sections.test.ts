"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import type { PeWindowsParseResult } from "../../../analyzers/pe/index.js";
import { PE_LAZY_SECTION_KEYS } from "../../../renderers/pe/lazy-section-shells.js";
import { FakeRoot, type FakeElement, createLazySection, installDom } from
  "../../fixtures/pe-lazy-section-dom.js";
import { createBasePe } from "../../fixtures/pe-renderer-headers-fixture.js";
import { enhancePeLazySections, refreshPeLazySection } from "../../../ui/pe-lazy-sections.js";

const createPe = (): PeWindowsParseResult => ({
  disassembly: { bitness: 32 },
  imports: { entries: [], thunkEntrySize: 4 },
  opt: { Magic: 0x10b },
  resources: {
    detail: [{
      entries: Array.from({ length: 125 }, (_, id) => ({
        id,
        langs: [{ codePage: 0, lang: 1033, size: 1 }],
        name: null
      })),
      typeName: "RCDATA"
    }],
    directories: [],
    paths: [],
    top: []
  }
}) as unknown as PeWindowsParseResult;

void test("PE lazy sections unmount heavy DOM and restore section state", () => {
  const { body, details, section } = createLazySection(PE_LAZY_SECTION_KEYS.resources);
  const root = new FakeRoot(section);
  const dom = installDom(section);
  try {
    enhancePeLazySections(root as unknown as ParentNode, createPe());
    assert.equal(body.innerHTML, "");

    details.open = true;
    root.toggleHandler?.({ target: details } as unknown as Event);
    assert.equal(section.dataset["peLazyMounted"], "true");
    assert.equal(body.pagedRoot?.dataset["pagedSortablePageIndex"], "0");

    body.nestedDetails!.open = true;
    body.filterControl!.value = "manifest";
    body.selectedRow!.setAttribute("aria-selected", "true");
    body.selectedRow!.dataset["selected"] = "true";
    body.selectedRow!.classList.add("selected");
    body.pagedRoot!.dataset["pagedSortablePageIndex"] = "2";
    body.pagedRoot!.dataset["pagedSortableSortColumn"] = "4";
    body.pagedRoot!.dataset["pagedSortableSortDirection"] = "descending";

    details.open = false;
    root.toggleHandler?.({ target: details } as unknown as Event);
    assert.equal(section.dataset["peLazyMounted"], "false");
    assert.equal(body.innerHTML, "");
    assert.equal(body.pagedRoot, null);

    details.open = true;
    root.toggleHandler?.({ target: details } as unknown as Event);
    assert.equal(body.nestedDetails?.open, true);
    assert.equal(body.filterControl?.value, "manifest");
    assert.equal(body.selectedRow?.getAttribute("aria-selected"), "true");
    assert.equal(body.selectedRow?.dataset["selected"], "true");
    const pagedRoot = body.pagedRoot as FakeElement | null;
    if (!pagedRoot) throw new Error("Expected remounted paged root");
    const pagedDataset = pagedRoot.dataset as Record<string, string | undefined>;
    assert.equal(pagedDataset["pagedSortablePageIndex"], "2");
    assert.equal(pagedDataset["pagedSortableSortColumn"], "4");
    assert.equal(pagedDataset["pagedSortableSortDirection"], "descending");

    assert.equal(refreshPeLazySection(PE_LAZY_SECTION_KEYS.resources, createPe()), true);
    assert.equal(section.dataset["peLazyMounted"], "true");
    assert.equal(body.filterControl?.value, "manifest");
  } finally {
    dom.restore();
  }
});

for (const key of Object.values(PE_LAZY_SECTION_KEYS)) {
  void test(`PE lazy section ${key} tolerates missing optional metadata`, () => {
    const { body, details, section } = createLazySection(key);
    const root = new FakeRoot(section);
    const dom = installDom(section);
    try {
      enhancePeLazySections(root as unknown as ParentNode, createBasePe());

      details.open = true;
      root.toggleHandler?.({ target: details } as unknown as Event);
      assert.equal(section.dataset["peLazyMounted"], "true");
      details.open = false;
      root.toggleHandler?.({ target: details } as unknown as Event);

      assert.equal(section.dataset["peLazyMounted"], "false");
      assert.equal(body.innerHTML, "");
    } finally {
      dom.restore();
    }
  });
}
