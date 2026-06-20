"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderInspectionContext } from "../../../ui/inspection-context.js";

const createElements = () => ({
  objectElement: { hidden: false, innerHTML: "", textContent: "" },
  relativePathElement: { hidden: false, innerHTML: "", textContent: "" },
  relativePathTermElement: { hidden: false, innerHTML: "", textContent: "" },
  sourceElement: { hidden: false, innerHTML: "", textContent: "" }
});

void test("inspection context renders direct source and object chips without a path", () => {
  const elements = createElements();
  renderInspectionContext(elements as unknown as {
    objectElement: HTMLElement;
    relativePathElement: HTMLElement;
    relativePathTermElement: HTMLElement;
    sourceElement: HTMLElement;
  }, { source: "selection", object: "file" });
  assert.match(elements.sourceElement.innerHTML, /class="opt sel".*>Selection<\/span>/);
  assert.match(elements.sourceElement.innerHTML, /class="opt dim">Navigation<\/span>/);
  assert.match(elements.objectElement.innerHTML, /class="opt sel".*>File<\/span>/);
  assert.match(elements.objectElement.innerHTML, /class="opt dim">Collection<\/span>/);
  assert.equal(elements.relativePathTermElement.hidden, true);
  assert.equal(elements.relativePathElement.hidden, true);
});

void test("inspection context renders a relative path for navigation", () => {
  const elements = createElements();
  renderInspectionContext(elements as unknown as {
    objectElement: HTMLElement;
    relativePathElement: HTMLElement;
    relativePathTermElement: HTMLElement;
    sourceElement: HTMLElement;
  }, { source: "navigation", object: "directory", relativePath: "docs/manual" });
  assert.match(elements.sourceElement.innerHTML, /class="opt sel".*>Navigation<\/span>/);
  assert.match(elements.objectElement.innerHTML, /class="opt sel".*>Directory<\/span>/);
  assert.equal(elements.relativePathElement.textContent, "docs/manual");
  assert.equal(elements.relativePathTermElement.hidden, false);
  assert.equal(elements.relativePathElement.hidden, false);
});
