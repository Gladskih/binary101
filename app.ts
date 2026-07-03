"use strict";
import { nowIsoString, formatHumanSize } from "./binary-utils.js";
import { detectBinaryType, parseForUi, type ParseForUiResult } from "./analyzers/index.js";
import { renderAnalysisIntoUi as renderParsedResult } from "./ui/render-analysis.js";
import { attachPreviewGuards, buildPreviewHtml } from "./ui/preview.js";
import { HASH_ALGORITHMS, computeAndDisplayHash, copyHashToClipboard, resetHashDisplay } from "./ui/hash-controls.js";
import { createFileActionClickHandler } from "./ui/file-actions.js";
import { isPeWindowsParseResult } from "./analyzers/pe/index.js";
import { handlePeEntrypointJumpClick } from "./ui/pe-entrypoint-navigation.js";
import { createAnalysisPanelActions } from "./ui/analysis-panel-actions.js";
import {
  refreshElfInstructionSetsPanel,
  refreshPeEntrypointDisassemblyPanel,
  refreshPeInstructionSetsPanel
} from "./ui/analysis-panel-refresh.js";
import { copyManifestPreviewToClipboard } from "./ui/manifest-preview-copy.js";
import { handleManifestTreeActionClick, syncManifestTreeControls } from "./ui/manifest-tree-controls.js";
import { captureOpenDetails, restoreOpenDetails } from "./ui/details-open-state.js";
import { enhanceSortableTables, handleSortableTableClick } from "./ui/sortable-tables.js";
import { enhanceAnalysisEntrypointExplorer, enhanceAnalysisPagedTables } from "./ui/analysis-paged-tables.js";
import { capturePagedSortableTableState } from "./ui/paged-sortable-tables.js";
import { enhancePeLazySections } from "./ui/pe-lazy-sections.js";
import { createDirectoryInspectionController, type DirectoryInspectionController } from "./ui/directory-inspection.js";
import { createInspectionNavigationController } from "./ui/inspection-navigation.js";
import { attachSelectionInputs } from "./ui/selection-inputs.js";
import { createFileInspectionContext } from "./ui/file-inspection-context.js";
import { setFileBinaryTypeLabel } from "./ui/file-type-label.js";
import {
  addAccessibleTooltip,
  addAccessibleTooltipToButton,
  enhanceAccessibleTooltips
} from "./ui/accessible-tooltips.js";
import { attachPeFileIconGuard, renderPeFileIcon } from "./ui/pe-file-icon.js";
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
  fileBinaryTypeDetailElement = getElement("fileBinaryTypeDetail") as HTMLElement,
  fileMimeTypeDetailElement = getElement("fileMimeTypeDetail") as HTMLElement,
  fileIconWrapElement = getElement("fileIconWrap") as HTMLElement,
  fileIconElement = getElement("fileIcon") as HTMLImageElement,
  analysisTermElement = getElement("analysisTerm") as HTMLElement,
  analysisValueElement = getElement("analysisValue") as HTMLElement,
  hashDetailsElement = getElement("hashDetails") as HTMLDetailsElement;
attachPeFileIconGuard(fileIconElement, fileIconWrapElement);
const fileInspectionContext = createFileInspectionContext(html);
const hashControls = HASH_ALGORITHMS.map(algorithm => ({
  algorithm,
  label: algorithm.label,
  valueElement: getElement(`${algorithm.id}Value`) as HTMLElement,
  buttonElement: getElement(`${algorithm.id}ComputeButton`) as HTMLButtonElement,
  copyButtonElement: getElement(`${algorithm.id}CopyButton`) as HTMLButtonElement,
  nativeHashBadgeElement: document.getElementById(`${algorithm.id}NativeBadge`) as HTMLButtonElement | null ?? undefined
}));
hashControls.forEach(control => {
  if (control.nativeHashBadgeElement) addAccessibleTooltipToButton(
    control.nativeHashBadgeElement, control.nativeHashBadgeElement.title
  );
});
let currentFile: File | null = null; let currentPreviewUrl: string | null = null;
let currentTypeLabel = ""; let currentParseResult: ParseForUiResult = { analyzer: null, parsed: null };
let fileInspectionGeneration = 0;
const setPreviewUrl = (url: string | null): void => {
  if (currentPreviewUrl) URL.revokeObjectURL(currentPreviewUrl);
  currentPreviewUrl = url;
};
const setStatusMessage = (message: string | null | undefined): void => { statusElement.textContent = message || ""; };
const formatAnalysisDuration = (durationMs: number): string =>
  durationMs < 1000 ? `${Math.max(0, Math.round(durationMs))} ms` : `${(durationMs / 1000).toFixed(2)} s`;
const renderResult = (result: ParseForUiResult): void => {
  const openDetails = captureOpenDetails(analysisValueElement);
  const pagedTables = capturePagedSortableTableState(analysisValueElement);
  renderParsedResult(result, {
    buildPreview: () =>
      buildPreviewHtml({ file: currentFile, typeLabel: currentTypeLabel, setPreviewUrl }),
    attachGuards: preview => attachPreviewGuards(preview, analysisValueElement, setStatusMessage),
    termElement: analysisTermElement,
    valueElement: analysisValueElement
  });
  enhanceSortableTables(analysisValueElement);
  enhanceAnalysisPagedTables(analysisValueElement, result, pagedTables);
  enhanceAnalysisEntrypointExplorer(analysisValueElement, result);
  enhanceAccessibleTooltips(fileInfoCardElement);
  restoreOpenDetails(analysisValueElement, openDetails, viewer => syncManifestTreeControls(viewer as Element));
  enhancePeLazySections(analysisValueElement, result.analyzer === "pe" && result.parsed ? result.parsed : null);
};
const getCurrentFile = (): File | null => currentFile;
const getCurrentParseResult = (): ParseForUiResult => currentParseResult;
const { peDisassembly, peEntrypointDisassembly, peOverlayScan, elfDisassembly } =
  createAnalysisPanelActions(getCurrentFile, getCurrentParseResult, setStatusMessage);
const fileActionClickHandler = createFileActionClickHandler({
  getParseResult: getCurrentParseResult, getFile: getCurrentFile, setStatusMessage
});
const cancelActiveAnalysis = (): void => {
  peDisassembly.cancel();
  peEntrypointDisassembly.cancel();
  peOverlayScan.cancel();
  elfDisassembly.cancel();
};
const resetFileInspectionView = (): void => {
  fileInspectionGeneration += 1;
  cancelActiveAnalysis();
  currentFile = null;
  currentTypeLabel = "";
  currentParseResult = { analyzer: null, parsed: null };
  renderPeFileIcon(null, "", fileIconElement, fileIconWrapElement);
  setPreviewUrl(null);
  fileInfoCardElement.hidden = true;
  analysisTermElement.hidden = true;
  analysisValueElement.hidden = true;
  analysisValueElement.innerHTML = "";
  fileAnalysisDurationDetailElement.textContent = "";
  hashDetailsElement.open = false;
  resetHashDisplay(...hashControls);
  fileInspectionContext.clear();
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
  contextElements: {
    objectElement: html("directoryObjectDetail"),
    relativePathElement: html("directoryRelativePathDetail"),
    relativePathTermElement: html("directoryRelativePathTerm"),
    sourceElement: html("directorySourceDetail")
  },
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
analysisValueElement.addEventListener("click", event => {
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
  if (handlePeEntrypointJumpClick(targetElement, analysisValueElement)) { event.preventDefault(); return; }
  const peAnalyzeButton = targetElement?.closest("#peInstructionSetsAnalyzeButton");
  const peCancelButton = targetElement?.closest("#peInstructionSetsCancelButton");
  const peEntrypointButton = targetElement?.closest("#peEntrypointDisassembleButton");
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
    refreshPeInstructionSetsPanel(currentParseResult.parsed);
    peDisassembly.start(currentFile, currentParseResult.parsed);
    return;
  }
  if (peCancelButton) {
    event.preventDefault();
    peDisassembly.cancel();
    return;
  }
  if (peEntrypointButton) {
    event.preventDefault();
    if (!currentFile) return;
    if (
      currentParseResult.analyzer !== "pe" ||
      !currentParseResult.parsed ||
      !isPeWindowsParseResult(currentParseResult.parsed)
    ) {
      return;
    }
    delete currentParseResult.parsed.entrypointDisassembly;
    refreshPeEntrypointDisassemblyPanel(currentParseResult.parsed);
    peEntrypointDisassembly.start(currentFile, currentParseResult.parsed);
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
    refreshElfInstructionSetsPanel(currentParseResult.parsed);
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
analysisValueElement.addEventListener("toggle", syncToggledManifestTree, true);
async function showFileInfo(file: File, context: Parameters<typeof fileInspectionContext.render>[0]): Promise<void> {
  const currentGeneration = fileInspectionGeneration + 1;
  fileInspectionGeneration = currentGeneration;
  cancelActiveAnalysis();
  directoryInspection.hide();
  currentFile = file;
  currentParseResult = { analyzer: null, parsed: null };
  renderPeFileIcon(null, "", fileIconElement, fileIconWrapElement);
  hashDetailsElement.open = false;
  resetHashDisplay(...hashControls);
  try {
    setPreviewUrl(null);
    fileInfoCardElement.hidden = true;
    analysisTermElement.hidden = true;
    analysisValueElement.hidden = true;
    analysisValueElement.innerHTML = "";
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
    fileInspectionContext.render(context);
    setFileBinaryTypeLabel(fileBinaryTypeDetailElement, typeLabel, addAccessibleTooltip);
    fileMimeTypeDetailElement.textContent = mimeType;
    fileInfoCardElement.hidden = false;
    setStatusMessage("Parsing file details...");
    const analysisStart = performance.now();
    const parsedResult = await parseForUi(file);
    if (fileInspectionGeneration !== currentGeneration) return;
    fileAnalysisDurationDetailElement.textContent = formatAnalysisDuration(performance.now() - analysisStart);
    currentParseResult = parsedResult;
    renderPeFileIcon(parsedResult, file.name, fileIconElement, fileIconWrapElement);
    renderResult(parsedResult);
    setStatusMessage(null);
  } catch (error) {
    if (fileInspectionGeneration !== currentGeneration) return;
    currentTypeLabel = "";
    renderPeFileIcon(null, "", fileIconElement, fileIconWrapElement);
    setPreviewUrl(null);
    setStatusMessage(
      `Unable to read file: ${error instanceof Error && error.message ? error.message : String(error)}`
    );
    fileAnalysisDurationDetailElement.textContent = "";
    analysisTermElement.hidden = true;
    analysisValueElement.hidden = true;
    analysisValueElement.innerHTML = "";
  }
}
hashControls.forEach(control => {
  control.buttonElement.addEventListener("click", () => {
    const file = currentFile;
    void computeAndDisplayHash(control.algorithm, file, control, () => currentFile === file);
  });
  control.copyButtonElement.addEventListener("click", () => {
    void copyHashToClipboard(control.valueElement).then(status => {
      setStatusMessage(status === "copied" ? `${control.label} copied.` : "Clipboard copy failed.");
    });
  });
});
