"use strict";
import { nowIsoString, formatHumanSize } from "./binary-utils.js";
import { detectBinaryType, parseForUi, type ParseForUiResult } from "./analyzers/index.js";
import { renderAnalysisIntoUi as renderParsedResult } from "./ui/render-analysis.js";
import { attachPreviewGuards, buildPreviewHtml } from "./ui/preview.js";
import { computeAndDisplayHash, copyHashToClipboard, resetHashDisplay } from "./ui/hash-controls.js";
import { createFileActionClickHandler } from "./ui/file-actions.js";
import { isPeWindowsParseResult } from "./analyzers/pe/index.js";
import { createPeDisassemblyController } from "./ui/pe-disassembly.js";
import { createElfDisassemblyController } from "./ui/elf-disassembly.js";
import { copyManifestPreviewToClipboard } from "./ui/manifest-preview-copy.js";
import { createPeOverlayScanActions } from "./ui/pe-overlay-scan.js";
import { handleManifestTreeActionClick, syncManifestTreeControls } from "./ui/manifest-tree-controls.js";
import { captureOpenDetails, restoreOpenDetails } from "./ui/details-open-state.js";
import { enhanceSortableTables, handleSortableTableClick } from "./ui/sortable-tables.js";
import { createDirectoryInspectionController } from "./ui/directory-inspection.js";
const getElement = (id: string) => document.getElementById(id)!;
const html = (id: string): HTMLElement => getElement(id) as HTMLElement;
const dropZoneElement = getElement("dropZone") as HTMLElement,
  fileInputElement = getElement("fileInput") as HTMLInputElement,
  statusElement = getElement("statusMessage") as HTMLElement,
  fileInfoCardElement = getElement("fileInfoCard") as HTMLElement,
  fileNameDetailElement = getElement("fileNameDetail") as HTMLElement,
  fileSizeDetailElement = getElement("fileSizeDetail") as HTMLElement,
  fileTimestampDetailElement = getElement("fileTimestampDetail") as HTMLElement,
  fileAnalysisDurationDetailElement = getElement("fileAnalysisDurationDetail") as HTMLElement,
  fileSourceDetailElement = getElement("fileSourceDetail") as HTMLElement,
  fileBinaryTypeDetailElement = getElement("fileBinaryTypeDetail") as HTMLElement,
  fileMimeTypeDetailElement = getElement("fileMimeTypeDetail") as HTMLElement,
  peDetailsTermElement = getElement("peDetailsTerm") as HTMLElement,
  peDetailsValueElement = getElement("peDetailsValue") as HTMLElement,
  sha256ValueElement = getElement("sha256Value") as HTMLElement,
  sha512ValueElement = getElement("sha512Value") as HTMLElement,
  sha256ButtonElement = getElement("sha256ComputeButton") as HTMLButtonElement,
  sha512ButtonElement = getElement("sha512ComputeButton") as HTMLButtonElement,
  sha256CopyButtonElement = getElement("sha256CopyButton") as HTMLButtonElement,
  sha512CopyButtonElement = getElement("sha512CopyButton") as HTMLButtonElement;
const sha256Controls = { valueElement: sha256ValueElement, buttonElement: sha256ButtonElement,
  copyButtonElement: sha256CopyButtonElement };
const sha512Controls = { valueElement: sha512ValueElement, buttonElement: sha512ButtonElement,
  copyButtonElement: sha512CopyButtonElement };
let currentFile: File | null = null;
let currentPreviewUrl: string | null = null;
let currentTypeLabel = "";
let currentParseResult: ParseForUiResult = { analyzer: null, parsed: null };
const setPreviewUrl = (url: string | null): void => {
  if (currentPreviewUrl) URL.revokeObjectURL(currentPreviewUrl);
  currentPreviewUrl = url;
};
const setStatusMessage = (message: string | null | undefined): void => { statusElement.textContent = message || ""; };
const formatAnalysisDuration = (durationMs: number): string =>
  durationMs < 1000 ? `${Math.max(0, Math.round(durationMs))} ms` : `${(durationMs / 1000).toFixed(2)} s`;
const snapshotFileList = (files: FileList): File[] =>
  Array.from({ length: files.length }, (_, index) => files.item(index)).filter((file): file is File => file != null);
const renderResult = (result: ParseForUiResult): void => {
  const openDetails = captureOpenDetails(peDetailsValueElement);
  renderParsedResult(result, {
    buildPreview: () =>
      buildPreviewHtml({ file: currentFile, typeLabel: currentTypeLabel, setPreviewUrl }),
    attachGuards: preview => attachPreviewGuards(preview, peDetailsValueElement, setStatusMessage),
    termElement: peDetailsTermElement,
    valueElement: peDetailsValueElement
  });
  enhanceSortableTables(peDetailsValueElement);
  restoreOpenDetails(peDetailsValueElement, openDetails, viewer => syncManifestTreeControls(viewer as Element));
};
const getCurrentFile = (): File | null => currentFile;
const getCurrentParseResult = (): ParseForUiResult => currentParseResult;
const peDisassembly = createPeDisassemblyController({ getCurrentFile, getCurrentParseResult, renderResult });
const peOverlayScan = createPeOverlayScanActions({
  getCurrentFile, getCurrentParseResult, renderResult, setStatusMessage
});
const elfDisassembly = createElfDisassemblyController({ getCurrentFile, getCurrentParseResult, renderResult });
const fileActionClickHandler = createFileActionClickHandler({
  getParseResult: getCurrentParseResult, getFile: getCurrentFile, setStatusMessage
});
const cancelActiveAnalysis = (): void => { peDisassembly.cancel(); peOverlayScan.cancel(); elfDisassembly.cancel(); };
const directoryInspection = createDirectoryInspectionController({
  openButtonElement: getElement("directoryOpenButton") as HTMLButtonElement,
  backButtonElement: getElement("directoryBackButton") as HTMLButtonElement,
  cardElement: html("directoryInfoCard"), nameElement: html("directoryName"),
  summaryElement: html("directorySummary"), progressWrapElement: html("directoryProgressWrap"),
  progressElement: getElement("directoryScanProgress") as HTMLProgressElement,
  progressTextElement: html("directoryScanProgressText"),
  folderSectionElement: html("directoryFoldersSection"), fileSectionElement: html("directoryFilesSection"),
  warningSectionElement: html("directoryWarningsSection"), folderTableBodyElement: html("directoryFolderListingBody"),
  fileTableBodyElement: html("directoryFileListingBody"), warningTableBodyElement: html("directoryWarningListingBody"),
  resetFileInspection: () => { cancelActiveAnalysis(); currentFile = null; setPreviewUrl(null);
    currentParseResult = { analyzer: null, parsed: null }; fileInfoCardElement.hidden = true; },
  setStatusMessage,
  openFile: showFileInfo
});
peDetailsValueElement.addEventListener("click", event => {
  const targetNode = event.target as Node | null;
  const targetElement = targetNode instanceof Element ? targetNode : targetNode?.parentElement ?? null;
  if (targetElement?.closest("[data-manifest-copy-button]")) {
    event.preventDefault();
    void copyManifestPreviewToClipboard(targetElement).then(status => {
      setStatusMessage(status === "copied" ? "Manifest XML copied." : "Clipboard copy failed.");
    });
    return;
  }
  if (handleManifestTreeActionClick(targetElement)) { event.preventDefault(); return; }
  if (handleSortableTableClick(targetElement)) { event.preventDefault(); return; }
  const peAnalyzeButton = targetElement?.closest("#peInstructionSetsAnalyzeButton");
  const peCancelButton = targetElement?.closest("#peInstructionSetsCancelButton");
  const elfAnalyzeButton = targetElement?.closest("#elfInstructionSetsAnalyzeButton");
  const elfCancelButton = targetElement?.closest("#elfInstructionSetsCancelButton");
  if (peAnalyzeButton) {
    event.preventDefault();
    if (!currentFile) return;
    if (
      currentParseResult.analyzer !== "pe" ||
      !currentParseResult.parsed ||
      !isPeWindowsParseResult(currentParseResult.parsed)
    ) {
      return;
    }
    delete currentParseResult.parsed.disassembly;
    renderResult(currentParseResult);
    peDisassembly.start(currentFile, currentParseResult.parsed);
    return;
  }
  if (peCancelButton) {
    event.preventDefault();
    peDisassembly.cancel();
    return;
  }
  if (peOverlayScan.handleClick(targetElement)) {
    event.preventDefault();
    return;
  }
  if (elfAnalyzeButton) {
    event.preventDefault();
    if (!currentFile) return;
    if (currentParseResult.analyzer !== "elf" || !currentParseResult.parsed) return;
    delete currentParseResult.parsed.disassembly;
    renderResult(currentParseResult);
    elfDisassembly.start(currentFile, currentParseResult.parsed);
    return;
  }
  if (elfCancelButton) {
    event.preventDefault();
    elfDisassembly.cancel();
    return;
  }
  fileActionClickHandler(event);
});
const syncToggledManifestTree = (event: Event): void => syncManifestTreeControls(event.target as Element | null);
peDetailsValueElement.addEventListener("toggle", syncToggledManifestTree, true);
async function showFileInfo(file: File, sourceDescription: string): Promise<void> {
  cancelActiveAnalysis();
  directoryInspection.hide();
  currentFile = file;
  currentParseResult = { analyzer: null, parsed: null };
  try {
    setPreviewUrl(null);
    fileInfoCardElement.hidden = true;
    peDetailsTermElement.hidden = true;
    peDetailsValueElement.hidden = true;
    peDetailsValueElement.innerHTML = "";
    setStatusMessage("Detecting file type...");
    const typeLabel = await detectBinaryType(file);
    currentTypeLabel = typeLabel || "";
    const timestampIso = nowIsoString();
    const sizeText = formatHumanSize(file.size);
    const mimeType = typeof file.type === "string" && file.type.length > 0 ? file.type : "Not provided by browser";
    fileNameDetailElement.textContent = file.name || "";
    fileSizeDetailElement.textContent = sizeText;
    fileTimestampDetailElement.textContent = timestampIso;
    fileSourceDetailElement.textContent = sourceDescription;
    fileBinaryTypeDetailElement.textContent = typeLabel;
    fileMimeTypeDetailElement.textContent = mimeType;
    fileInfoCardElement.hidden = false;
    setStatusMessage("Parsing file details...");
    const analysisStart = performance.now();
    const parsedResult = await parseForUi(file);
    fileAnalysisDurationDetailElement.textContent = formatAnalysisDuration(performance.now() - analysisStart);
    currentParseResult = parsedResult;
    renderResult(parsedResult);
    resetHashDisplay(sha256Controls, sha512Controls);
    setStatusMessage(null);
  } catch (error) {
    currentTypeLabel = "";
    setPreviewUrl(null);
    setStatusMessage(
      `Unable to read file: ${error instanceof Error && error.message ? error.message : String(error)}`
    );
    fileAnalysisDurationDetailElement.textContent = "";
    peDetailsTermElement.hidden = true;
    peDetailsValueElement.hidden = true;
    peDetailsValueElement.innerHTML = "";
  }
}
const openFileSelection = (files: readonly File[], sourceDescription: string): void => {
  if (files.length === 0) {
    setStatusMessage("No file selected.");
    return;
  }
  void directoryInspection.openFiles(files, sourceDescription);
};
const handleSelectedFiles = (files: FileList | null): void =>
  openFileSelection(files ? snapshotFileList(files) : [], "File selection");
["dragenter", "dragover"].forEach(eventName =>
  dropZoneElement.addEventListener(eventName, event => {
    event.preventDefault();
    dropZoneElement.classList.add("dragover");
  })
);
["dragleave", "drop"].forEach(eventName =>
  dropZoneElement.addEventListener(eventName, event => {
    event.preventDefault();
    if (event.type === "drop") {
      const dragEvent = event as DragEvent;
      const dataTransfer = dragEvent.dataTransfer;
      if (!dataTransfer) {
        setStatusMessage("Drop: cannot access data.");
      } else {
        const droppedFiles = snapshotFileList(dataTransfer.files);
        void directoryInspection.openDroppedItems(dataTransfer.items, "Drop").then(openedItems => {
          if (!openedItems) openFileSelection(droppedFiles, "Drop");
        });
      }
    }
    dropZoneElement.classList.remove("dragover");
  })
);
dropZoneElement.addEventListener("keydown", event => {
  if (event.key === " " || event.key === "Enter") {
    event.preventDefault();
    fileInputElement.click();
  }
});
fileInputElement.addEventListener("change", event => {
  const input = event.currentTarget;
  if (!(input instanceof HTMLInputElement)) return;
  handleSelectedFiles(input.files);
  input.value = "";
});
const handlePaste = async (event: ClipboardEvent): Promise<void> => {
  const clipboardData = event.clipboardData;
  if (!clipboardData) {
    setStatusMessage("Paste: clipboard not available.");
    return;
  }
  const files = clipboardData.files ? snapshotFileList(clipboardData.files) : [];
  if (files.length > 0) {
    await directoryInspection.openFiles(files, files.length === 1 ? "Paste (file)" : "Paste (files)");
    return;
  }
  const items = clipboardData.items ? Array.from(clipboardData.items) : [];
  const openedItems = await directoryInspection.openDroppedItems(
    { length: items.length, item: index => items[index] ?? null },
    "Paste"
  );
  if (openedItems) return;
  const textItems = items.filter(item => item.kind === "string");
  if (textItems.length !== 1) {
    setStatusMessage("Paste: unsupported clipboard payload.");
    return;
  }
  const [textItem] = textItems;
  if (!textItem) {
    setStatusMessage("Paste: clipboard item missing.");
    return;
  }
  const text = await new Promise<string | null>(resolve => textItem.getAsString(resolve));
  if (typeof text !== "string" || text.length === 0) {
    setStatusMessage("Paste: empty text.");
    return;
  }
  const syntheticFile = new File([text], "clipboard.bin", { type: "application/octet-stream" });
  await showFileInfo(syntheticFile, "Paste (clipboard data)");
};
window.addEventListener("paste", event => {
  void handlePaste(event as ClipboardEvent);
});
sha256ButtonElement.addEventListener("click", () => {
  void computeAndDisplayHash("SHA-256", currentFile, sha256Controls);
});
sha512ButtonElement.addEventListener("click", () => {
  void computeAndDisplayHash("SHA-512", currentFile, sha512Controls);
});
sha256CopyButtonElement.addEventListener("click", () => {
  void copyHashToClipboard(sha256ValueElement).then(status => {
    setStatusMessage(status === "copied" ? "SHA-256 copied." : "Clipboard copy failed.");
  });
});
sha512CopyButtonElement.addEventListener("click", () => {
  void copyHashToClipboard(sha512ValueElement).then(status => {
    setStatusMessage(status === "copied" ? "SHA-512 copied." : "Clipboard copy failed.");
  });
});
