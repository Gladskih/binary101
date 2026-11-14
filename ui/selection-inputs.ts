import type { DirectoryInspectionController } from "./directory-inspection.js";
import type { DirectInspectionSource, InspectionContext } from "./inspection-context.js";
import { captureClipboardEntries } from "./clipboard-snapshot.js";
import type { ClipboardEntry } from "./clipboard-snapshot.js";
import { formatAccessError } from "./directory-handles.js";

type StatusWriter = (message: string | null | undefined) => void;
type FileOpener = (file: File, context: InspectionContext) => Promise<void>;

interface SelectionInputConfig {
  readonly directoryInspection: DirectoryInspectionController;
  readonly dropZoneElement: HTMLElement;
  readonly fileInputElement: HTMLInputElement;
  readonly openFile: FileOpener;
  readonly setStatusMessage: StatusWriter;
  readonly chooseClipboardEntries: (
    entries: readonly ClipboardEntry[]
  ) => Promise<readonly ClipboardEntry[]>;
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
  let inspectedFile: File | null = null;
  const inspectSelection = (files: FileList): void => {
    inspectedFile = files.length === 1 ? files.item(0) : null;
    void openFileSelection(config, snapshotFileList(files), "selection");
  };
  // Retain the selection so the native picker can recognize a repeat selection as a dismissal.
  // https://html.spec.whatwg.org/multipage/input.html#file-upload-state-(type=file)
  input.addEventListener("change", () => {
    if (input.files?.length) inspectSelection(input.files);
  });
  input.addEventListener("cancel", () => {
    const files = input.files;
    const file = files?.length === 1 ? files.item(0) : null;
    // Some browsers return a fresh snapshot even when the path stays the same.
    if (files && file && inspectedFile && file !== inspectedFile &&
      (file.size !== inspectedFile.size || file.lastModified !== inspectedFile.lastModified)) {
      inspectSelection(files);
    }
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

const openClipboardSelection = async (
  config: SelectionInputConfig, entries: readonly ClipboardEntry[]
): Promise<void> => {
  const entry = entries[0];
  if (!entry) return;
  if (entry.kind === "unavailable") {
    config.setStatusMessage(`Paste: ${entry.error} Use Open files or drag a file here.`);
  } else if (entry.kind === "text") {
    await config.openFile(new File([entry.text], "clipboard.bin", {
      type: entry.type || "text/plain"
    }), { source: "paste", object: "file" });
  } else if (entries.every(entry => entry.kind === "file")) {
    await config.directoryInspection.openFiles(entries.map(entry => entry.file), "paste");
  } else {
    const handles = entries.flatMap(entry => entry.kind === "handle" ? [entry.handle] :
      entry.kind === "file" ? [{ kind: "file", name: entry.file.name,
        getFile: async () => entry.file }] : []);
    await config.directoryInspection.openDroppedItems({ length: handles.length,
      item: index => handles[index] ? { kind: "file",
        getAsFileSystemHandle: async () => handles[index]! } : null }, "paste");
  }
};

const handlePaste = async (
  config: SelectionInputConfig, event: ClipboardEvent, isCurrent: () => boolean
): Promise<void> => {
  const clipboardData = event.clipboardData;
  if (!clipboardData) {
    config.setStatusMessage("Paste: clipboard not available.");
    return;
  }
  try {
    const entries = await captureClipboardEntries(Array.from(clipboardData.items ?? []),
      clipboardData.files ? snapshotFileList(clipboardData.files) : []);
    if (!isCurrent()) return;
    const selected = await config.chooseClipboardEntries(entries);
    if (!isCurrent()) return;
    if (!entries.length) {
      config.setStatusMessage("Paste: no file or readable format received. " +
        "Use Open files or drag a file here.");
      return;
    }
    config.setStatusMessage(null);
    await openClipboardSelection(config, selected);
  } catch (error) {
    if (isCurrent()) config.setStatusMessage(`Paste: ${formatAccessError(error)}`);
  }
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
  let pasteGeneration = 0;
  window.addEventListener("paste", event => {
    if (event.target instanceof Element &&
      event.target.closest("input, textarea, [contenteditable]")) return;
    const generation = ++pasteGeneration;
    void handlePaste(config, event as ClipboardEvent, () => generation === pasteGeneration);
  });
};

export { attachSelectionInputs };
export type { SelectionInputConfig };
