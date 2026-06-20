"use strict";

import { renderInspectionContext } from "./inspection-context.js";
import type { InspectionContext, InspectionContextElements } from "./inspection-context.js";

interface FileInspectionContextController {
  clear(): void;
  render(context: InspectionContext): void;
}

const createFileInspectionContext = (
  getElement: (id: string) => HTMLElement
): FileInspectionContextController => {
  const elements: InspectionContextElements = {
    objectElement: getElement("fileObjectDetail"),
    relativePathElement: getElement("fileRelativePathDetail"),
    relativePathTermElement: getElement("fileRelativePathTerm"),
    sourceElement: getElement("fileSourceDetail")
  };
  return {
    clear: () => { renderInspectionContext(elements, null); },
    render: context => { renderInspectionContext(elements, context); }
  };
};

export { createFileInspectionContext };
export type { FileInspectionContextController };
