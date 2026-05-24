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
import {
  createDirectoryInspectionController,
  type DirectoryInspectionController
} from "./ui/directory-inspection.js";
import { createInspectionNavigationController } from "./ui/inspection-navigation.js";
import { attachSelectionInputs } from "./ui/selection-inputs.js";
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
let fileInspectionGeneration = 0;
const setPreviewUrl = (url: string | null): void => {
  if (currentPreviewUrl) URL.revokeObjectURL(currentPreviewUrl);
  currentPreviewUrl = url;
};
const setStatusMessage = (message: string | null | undefined): void => { statusElement.textContent = message || ""; };
const formatAnalysisDuration = (durationMs: number): string =>
  durationMs < 1000 ? `${Math.max(0, Math.round(durationMs))} ms` : `${(durationMs / 1000).toFixed(2)} s`;
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
const resetFileInspectionView = (): void => {
  fileInspectionGeneration += 1;
  cancelActiveAnalysis();
  currentFile = null;
  currentTypeLabel = "";
  currentParseResult = { analyzer: null, parsed: null };
  setPreviewUrl(null);
  fileInfoCardElement.hidden = true;
  peDetailsTermElement.hidden = true;
  peDetailsValueElement.hidden = true;
  peDetailsValueElement.innerHTML = "";
  fileAnalysisDurationDetailElement.textContent = "";
  resetHashDisplay(sha256Controls, sha512Controls);
};
const showEmptyInspection = (message: string | null): void => {
  directoryInspection.hide();
  resetFileInspectionView();
  setStatusMessage(message);
};
const inspectionNavigation = createInspectionNavigationController({
  openDirectoryRoute: route => { void directoryInspection.showRoute(route); },
  openEmptyRoute: showEmptyInspection,
  openFileRoute: showFileInfo
});
const directoryInspection: DirectoryInspectionController = createDirectoryInspectionController({
  openButtonElement: getElement("directoryOpenButton") as HTMLButtonElement,
  cardElement: html("directoryInfoCard"), nameElement: html("directoryName"),
  summaryElement: html("directorySummary"), progressWrapElement: html("directoryProgressWrap"),
  progressElement: getElement("directoryScanProgress") as HTMLProgressElement,
  progressTextElement: html("directoryScanProgressText"),
  folderSectionElement: html("directoryFoldersSection"), fileSectionElement: html("directoryFilesSection"),
  warningSectionElement: html("directoryWarningsSection"), folderTableBodyElement: html("directoryFolderListingBody"),
  fileTableBodyElement: html("directoryFileListingBody"), warningTableBodyElement: html("directoryWarningListingBody"),
  resetFileInspection: resetFileInspectionView,
  setStatusMessage,
  openFile: inspectionNavigation.openFile,
  openDirectory: inspectionNavigation.openDirectory
});
inspectionNavigation.initialize();
attachSelectionInputs({
  directoryInspection,
  dropZoneElement,
  fileInputElement,
  openFile: inspectionNavigation.openFile,
  setStatusMessage
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
  const currentGeneration = fileInspectionGeneration + 1;
  fileInspectionGeneration = currentGeneration;
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
    if (fileInspectionGeneration !== currentGeneration) return;
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
    if (fileInspectionGeneration !== currentGeneration) return;
    fileAnalysisDurationDetailElement.textContent = formatAnalysisDuration(performance.now() - analysisStart);
    currentParseResult = parsedResult;
    renderResult(parsedResult);
    resetHashDisplay(sha256Controls, sha512Controls);
    setStatusMessage(null);
  } catch (error) {
    if (fileInspectionGeneration !== currentGeneration) return;
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
