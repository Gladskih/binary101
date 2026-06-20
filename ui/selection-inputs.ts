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

const openFileSelection = (
  config: SelectionInputConfig,
  files: readonly File[],
  source: DirectInspectionSource
): void => {
  if (files.length === 0) {
    config.setStatusMessage("No file selected.");
    return;
  }
  void config.directoryInspection.openFiles(files, source);
};

const handleDroppedFiles = (config: SelectionInputConfig, event: Event): void => {
  const dataTransfer = (event as DragEvent).dataTransfer;
  if (!dataTransfer) {
    config.setStatusMessage("Drop: cannot access data.");
    return;
  }
  const droppedFiles = snapshotFileList(dataTransfer.files);
  void config.directoryInspection.openDroppedItems(dataTransfer.items, "drop").then(openedItems => {
    if (!openedItems) openFileSelection(config, droppedFiles, "drop");
  });
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

const attachSelectionInputs = (config: SelectionInputConfig): void => {
  ["dragenter", "dragover"].forEach(eventName =>
    config.dropZoneElement.addEventListener(eventName, event => {
      event.preventDefault();
      config.dropZoneElement.classList.add("dragover");
    })
  );
  ["dragleave", "drop"].forEach(eventName =>
    config.dropZoneElement.addEventListener(eventName, event => {
      event.preventDefault();
      if (event.type === "drop") handleDroppedFiles(config, event);
      config.dropZoneElement.classList.remove("dragover");
    })
  );
  config.dropZoneElement.addEventListener("keydown", event => {
    if (event.key !== " " && event.key !== "Enter") return;
    event.preventDefault();
    config.fileInputElement.click();
  });
  config.fileInputElement.addEventListener("change", event => {
    const input = event.currentTarget;
    if (!(input instanceof HTMLInputElement)) return;
    openFileSelection(config, input.files ? snapshotFileList(input.files) : [], "selection");
    input.value = "";
  });
  window.addEventListener("paste", event => { void handlePaste(config, event as ClipboardEvent); });
};

export { attachSelectionInputs };
export type { SelectionInputConfig };
