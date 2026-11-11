"use strict";

import type { DirectoryInspectionController } from "./directory-inspection.js";
import type { DirectInspectionSource, InspectionContext } from "./inspection-context.js";

type StatusWriter = (message: string | null | undefined) => void;
type FileOpener = (file: File, context: InspectionContext) => Promise<void>;

interface SelectionInputConfig {
  readonly directoryInspection: DirectoryInspectionController;
  readonly dropZoneElement: HTMLElement;
  readonly fileInputElement: HTMLInputElement;
  readonly openFile: FileOpener;
  readonly setStatusMessage: StatusWriter;
}

const snapshotFileList = (files: FileList): File[] =>
  Array.from({ length: files.length }, (_, index) => files.item(index)).filter((file): file is File => file != null);

const openFileSelection = async (
  config: SelectionInputConfig,
  files: readonly File[],
  source: DirectInspectionSource
): Promise<void> => {
  if (files.length === 0) {
    config.setStatusMessage("No file selected.");
    return;
  }
  await config.directoryInspection.openFiles(files, source);
};

const attachFilePicker = (config: SelectionInputConfig): void => {
  const input = config.fileInputElement;
  let current: Promise<void> | null = null;
  const openSelection = async (files: FileList): Promise<void> => {
    const inspection = openFileSelection(config, snapshotFileList(files), "selection");
    current = inspection;
    try {
      await inspection;
    } finally {
      if (current === inspection) {
        input.value = "";
        current = null;
      }
    }
  };
  // Retain the selection so the native picker can recognize a repeat selection as a dismissal.
  // https://html.spec.whatwg.org/multipage/input.html#file-upload-state-(type=file)
  input.addEventListener("change", () => {
    if (input.files?.length) void openSelection(input.files);
  });
};

const handleDroppedFiles = async (config: SelectionInputConfig, event: Event): Promise<void> => {
  const dataTransfer = (event as DragEvent).dataTransfer;
  if (!dataTransfer) {
    config.setStatusMessage("Drop: cannot access data.");
    return;
  }
  const droppedFiles = snapshotFileList(dataTransfer.files);
  const openedItems = await config.directoryInspection.openDroppedItems(dataTransfer.items, "drop");
  if (!openedItems) await openFileSelection(config, droppedFiles, "drop");
};

const handlePaste = async (
  config: SelectionInputConfig,
  event: ClipboardEvent
): Promise<void> => {
  const clipboardData = event.clipboardData;
  if (!clipboardData) {
    config.setStatusMessage("Paste: clipboard not available.");
    return;
  }
  const files = clipboardData.files ? snapshotFileList(clipboardData.files) : [];
  const items = clipboardData.items ? Array.from(clipboardData.items) : [];
  const openedItems = await config.directoryInspection.openDroppedItems(
    { length: items.length, item: index => items[index] ?? null },
    "paste"
  );
  if (openedItems) return;
  if (files.length > 0) {
    await config.directoryInspection.openFiles(files, "paste");
    return;
  }
  const textItems = items.filter(item => item.kind === "string");
  if (textItems.length !== 1) {
    config.setStatusMessage("Paste: unsupported clipboard payload.");
    return;
  }
  const [textItem] = textItems;
  if (!textItem) {
    config.setStatusMessage("Paste: clipboard item missing.");
    return;
  }
  const text = await new Promise<string | null>(resolve => textItem.getAsString(resolve));
  if (typeof text !== "string" || text.length === 0) {
    config.setStatusMessage("Paste: empty text.");
    return;
  }
  await config.openFile(
    new File([text], "clipboard.bin", { type: "application/octet-stream" }),
    { source: "paste", object: "file" }
  );
};

const attachDocumentFileDrop = (config: SelectionInputConfig): void => {
  let dragDepth = 0;
  document.addEventListener("dragenter", event => {
    if (!event.dataTransfer?.types.includes("Files")) return;
    dragDepth += 1;
    document.body.classList.add("draggingFiles");
  });
  document.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) document.body.classList.remove("draggingFiles");
  });
  document.addEventListener("dragover", event => {
    if (event.dataTransfer?.types.includes("Files")) event.preventDefault();
  });
  document.addEventListener("drop", event => {
    dragDepth = 0;
    document.body.classList.remove("draggingFiles");
    if (!event.dataTransfer?.types.includes("Files")) return;
    event.preventDefault();
    if (event.target instanceof Node && config.dropZoneElement.contains(event.target)) return;
    void handleDroppedFiles(config, event);
  });
};

const attachSelectionInputs = (config: SelectionInputConfig): void => {
  attachDocumentFileDrop(config);
  ["dragenter", "dragover"].forEach(eventName =>
    config.dropZoneElement.addEventListener(eventName, event => {
      event.preventDefault();
      config.dropZoneElement.classList.add("dragover");
    })
  );
  ["dragleave", "drop"].forEach(eventName =>
    config.dropZoneElement.addEventListener(eventName, event => {
      event.preventDefault();
      if (event.type === "drop") void handleDroppedFiles(config, event);
      config.dropZoneElement.classList.remove("dragover");
    })
  );
  config.dropZoneElement.addEventListener("click", () => config.fileInputElement.click());
  attachFilePicker(config);
  window.addEventListener("paste", event => {
    if (event.target instanceof Element &&
      event.target.closest("input, textarea, [contenteditable]")) return;
    void handlePaste(config, event as ClipboardEvent);
  });
};

export { attachSelectionInputs };
export type { SelectionInputConfig };
