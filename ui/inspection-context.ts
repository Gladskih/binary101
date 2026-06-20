"use strict";

type InspectionSource = "selection" | "paste" | "drop" | "navigation";
type DirectInspectionSource = Exclude<InspectionSource, "navigation">;
type TransferInspectionSource = Extract<DirectInspectionSource, "paste" | "drop">;
type InspectionObject = "file" | "directory" | "collection";

type InspectionContext =
  | {
    readonly source: DirectInspectionSource;
    readonly object: InspectionObject;
  }
  | { readonly source: "navigation"; readonly object: InspectionObject; readonly relativePath: string };

interface InspectionContextElements {
  readonly objectElement: HTMLElement;
  readonly relativePathElement: HTMLElement;
  readonly relativePathTermElement: HTMLElement;
  readonly sourceElement: HTMLElement;
}

const inspectionSourceLabels: Readonly<Record<InspectionSource, string>> = {
  selection: "Selection",
  paste: "Paste",
  drop: "Drop",
  navigation: "Navigation"
};

const inspectionObjectLabels: Readonly<Record<InspectionObject, string>> = {
  file: "File",
  directory: "Directory",
  collection: "Collection"
};

const renderOptionChips = <Value extends string>(
  element: HTMLElement,
  labels: Readonly<Record<Value, string>>,
  selectedValue: Value
): void => {
  element.innerHTML = Object.entries<string>(labels).map(([value, label]) => {
    const selected = value === selectedValue;
    const currentAttribute = selected ? ` aria-current="true"` : "";
    return `<span class="opt ${selected ? "sel" : "dim"}"${currentAttribute}>${label}</span>`;
  }).join("");
};

const renderInspectionContext = (
  elements: InspectionContextElements,
  context: InspectionContext | null
): void => {
  if (context) {
    renderOptionChips(elements.sourceElement, inspectionSourceLabels, context.source);
    renderOptionChips(elements.objectElement, inspectionObjectLabels, context.object);
  } else {
    elements.sourceElement.innerHTML = "";
    elements.objectElement.innerHTML = "";
  }
  const relativePath = context?.source === "navigation" ? context.relativePath : "";
  elements.relativePathTermElement.hidden = relativePath.length === 0;
  elements.relativePathElement.hidden = relativePath.length === 0;
  elements.relativePathElement.textContent = relativePath;
};

export { renderInspectionContext };
export type {
  DirectInspectionSource,
  InspectionContext,
  InspectionContextElements,
  InspectionObject,
  InspectionSource,
  TransferInspectionSource
};
