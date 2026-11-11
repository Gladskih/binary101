import { nowIsoString, formatHumanSize } from "./binary-utils.js";
import { detectBinaryType, type ParseForUiResult } from "./analyzers/index.js";
import { createInspectionFileParser } from "./ui/inspection-file-parser.js";
import { renderAnalysisIntoUi as renderParsedResult } from "./ui/render-analysis.js";
import { attachPreviewGuards, buildPreviewHtml } from "./ui/preview.js";
import { createHashControls, computeAndDisplayHash, copyHashToClipboard, resetHashDisplay } from "./ui/hash-controls.js";
import { createFileActionClickHandler } from "./ui/file-actions.js";
import { isPeWindowsParseResult } from "./analyzers/pe/index.js";
import { handlePeEntrypointJumpClick } from "./ui/pe-entrypoint-navigation.js";
import { createAnalysisPanelActions } from "./ui/analysis-panel-actions.js";
import { refreshElfInstructionSetsPanel, refreshPeEntrypointDisassemblyPanel,
  refreshPeInstructionSetsPanel } from "./ui/analysis-panel-refresh.js";
import { copyManifestPreviewToClipboard } from "./ui/manifest-preview-copy.js";
import { handleManifestTreeActionClick, syncManifestTreeControls } from "./ui/manifest-tree-controls.js";
import { captureOpenDetails, restoreOpenDetails } from "./ui/details-open-state.js";
import { enhanceSortableTables, handleSortableTableClick } from "./ui/sortable-tables.js";
import { enhanceAnalysisEntrypointExplorer, enhanceAnalysisPagedTables } from "./ui/analysis-paged-tables.js";
import { capturePagedSortableTableState } from "./ui/paged-sortable-tables.js";
import { enhancePeLazySections } from "./ui/pe-lazy-sections.js";
import { enhanceElfLazySections } from "./ui/elf-lazy-sections.js";
import { createDirectoryInspectionController, type DirectoryInspectionController } from "./ui/directory-inspection.js";
import { createInspectionNavigationController } from "./ui/inspection-navigation.js";
import { attachSelectionInputs } from "./ui/selection-inputs.js";
import { createFileInspectionContext } from "./ui/file-inspection-context.js";
import { setFileBinaryTypeLabel, setFileSubtypeLabel } from "./ui/file-type-label.js";
import { addAccessibleTooltip, enhanceAccessibleTooltips } from "./ui/accessible-tooltips.js";
import { attachPeFileIconGuard, renderPeFileIcon } from "./ui/pe-file-icon.js";
import { createSwfBodyAnalysis } from "./ui/swf-analysis.js";
import { createInspectionWorkspace } from "./ui/inspection-workspace.js";
const getElement = (id: string) => document.getElementById(id)!;
const dropZoneElement = getElement("dropZone") as HTMLElement,
  fileInputElement = getElement("fileInput") as HTMLInputElement,
  statusElement = getElement("statusMessage") as HTMLElement,
  fileInfoCardElement = getElement("fileInfoCard") as HTMLElement,
  fileNameDetailElement = getElement("fileNameDetail") as HTMLElement,
  fileSizeDetailElement = getElement("fileSizeDetail") as HTMLElement,
  fileTimestampDetailElement = getElement("fileTimestampDetail") as HTMLElement,
  fileAnalysisDurationDetailElement = getElement("fileAnalysisDurationDetail") as HTMLElement,
  fileAnalysisProgressElement = getElement("fileAnalysisProgress"),
  fileBinaryTypeDetailElement = getElement("fileBinaryTypeDetail") as HTMLElement,
  fileSubtypeTermElement = getElement("fileSubtypeTerm") as HTMLElement,
  fileSubtypeDetailElement = getElement("fileSubtypeDetail") as HTMLElement,
  fileMimeTypeDetailElement = getElement("fileMimeTypeDetail") as HTMLElement,
  fileIconWrapElement = getElement("fileIconWrap") as HTMLElement,
  fileIconElement = getElement("fileIcon") as HTMLImageElement,
  analysisTermElement = getElement("analysisTerm") as HTMLElement,
  analysisValueElement = getElement("analysisValue") as HTMLElement;
attachPeFileIconGuard(fileIconElement, fileIconWrapElement);
const fileInspectionContext = createFileInspectionContext(getElement);
const inspectionWorkspace = createInspectionWorkspace(document);
const hashControls = createHashControls(document);
let currentFile: File | null = null; let currentPreviewUrl: string | null = null;
let currentTypeLabel = ""; let currentParseResult: ParseForUiResult = { analyzer: null, parsed: null };
let fileInspectionGeneration = 0;
const setPreviewUrl = (url: string | null): void => {
  if (currentPreviewUrl) URL.revokeObjectURL(currentPreviewUrl);
  currentPreviewUrl = url;
};
const setStatusMessage = (message: string | null | undefined): void => { statusElement.textContent = message || ""; };
const fileParser = createInspectionFileParser(fileAnalysisProgressElement,
  fileAnalysisProgressElement.querySelector("progress")!, getElement("fileAnalysisPercent"),
  () => setStatusMessage(null));
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
  enhanceElfLazySections(analysisValueElement, result.analyzer === "elf" ? result.parsed : null);
  swfBodyAnalysis.start();
  inspectionWorkspace.completeAnalysis(result);
};
const getCurrentFile = (): File | null => currentFile;
const getCurrentParseResult = (): ParseForUiResult => currentParseResult;
const swfBodyAnalysis = createSwfBodyAnalysis(getCurrentFile, getCurrentParseResult, renderResult);
const { peDisassembly, peEntrypointDisassembly, peOverlayScan, elfDisassembly } =
  createAnalysisPanelActions(getCurrentFile, getCurrentParseResult, setStatusMessage);
const fileActionClickHandler = createFileActionClickHandler({
  getParseResult: getCurrentParseResult, getFile: getCurrentFile, setStatusMessage
});
const cancelActiveAnalysis = (): void => {
  fileParser.cancel();
  [peDisassembly, peEntrypointDisassembly, peOverlayScan, elfDisassembly, swfBodyAnalysis]
    .forEach(panel => panel.cancel());
};
const resetFileInspectionView = (): void => {
  fileInspectionGeneration += 1;
  cancelActiveAnalysis();
  fileInputElement.value = "";
  currentFile = null;
  currentTypeLabel = "";
  currentParseResult = { analyzer: null, parsed: null };
  renderPeFileIcon(null, "", fileIconElement, fileIconWrapElement);
  setFileSubtypeLabel(fileSubtypeTermElement, fileSubtypeDetailElement, currentParseResult);
  setPreviewUrl(null);
  fileInfoCardElement.hidden = true;
  analysisTermElement.hidden = true;
  analysisValueElement.hidden = true;
  analysisValueElement.innerHTML = "";
  fileAnalysisDurationDetailElement.textContent = "";
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
  cardElement: getElement("directoryInfoCard"), nameElement: getElement("directoryName"),
  contextElements: {
    objectElement: getElement("directoryObjectDetail"),
    relativePathElement: getElement("directoryRelativePathDetail"),
    relativePathTermElement: getElement("directoryRelativePathTerm"),
    sourceElement: getElement("directorySourceDetail")
  },
  summaryElement: getElement("directorySummary"), progressWrapElement: getElement("directoryProgressWrap"),
  progressElement: getElement("directoryScanProgress") as HTMLProgressElement,
  progressTextElement: getElement("directoryScanProgressText"),
  folderSectionElement: getElement("directoryFoldersSection"), fileSectionElement: getElement("directoryFilesSection"),
  warningSectionElement: getElement("directoryWarningsSection"), folderTableBodyElement: getElement("directoryFolderListingBody"),
  fileTableBodyElement: getElement("directoryFileListingBody"), warningTableBodyElement: getElement("directoryWarningListingBody"),
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
  if (peEntrypointDisassembly.handleClick(targetElement)) { event.preventDefault(); return; }
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
  if (fileInputElement.files?.item(0) !== file) fileInputElement.value = "";
  const currentGeneration = fileInspectionGeneration + 1;
  fileInspectionGeneration = currentGeneration;
  fileAnalysisDurationDetailElement.textContent = "";
  cancelActiveAnalysis();
  directoryInspection.hide();
  currentFile = file;
  currentParseResult = { analyzer: null, parsed: null };
  renderPeFileIcon(null, "", fileIconElement, fileIconWrapElement);
  resetHashDisplay(...hashControls);
  try {
    setPreviewUrl(null);
    fileInfoCardElement.hidden = true;
    analysisTermElement.hidden = true;
    analysisValueElement.hidden = true;
    analysisValueElement.innerHTML = "";
    inspectionWorkspace.begin(context);
    setStatusMessage("Detecting file type...");
    const typeLabel = await detectBinaryType(file);
    if (fileInspectionGeneration !== currentGeneration) return;
    currentTypeLabel = typeLabel || "";
    fileNameDetailElement.textContent = file.name || "";
    fileSizeDetailElement.textContent = formatHumanSize(file.size);
    fileTimestampDetailElement.textContent = nowIsoString();
    fileInspectionContext.render(context);
    setFileBinaryTypeLabel(fileBinaryTypeDetailElement, typeLabel, addAccessibleTooltip);
    setFileSubtypeLabel(fileSubtypeTermElement, fileSubtypeDetailElement, currentParseResult);
    fileMimeTypeDetailElement.textContent = file.type || "Not provided by browser";
    fileInfoCardElement.hidden = false;
    inspectionWorkspace.revealFile();
    setStatusMessage("Parsing file details...");
    const analysisStart = performance.now();
    const parsedResult = await fileParser.parse(file);
    if (fileInspectionGeneration !== currentGeneration) return;
    setFileSubtypeLabel(fileSubtypeTermElement, fileSubtypeDetailElement, parsedResult);
    fileAnalysisDurationDetailElement.textContent = formatAnalysisDuration(performance.now() - analysisStart);
    currentParseResult = parsedResult;
    renderPeFileIcon(parsedResult, file.name, fileIconElement, fileIconWrapElement);
    renderResult(parsedResult);
    setStatusMessage(null);
  } catch (error) {
    if (fileInspectionGeneration !== currentGeneration) return;
    fileInputElement.value = "";
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
  } finally {
    if (fileInspectionGeneration === currentGeneration) fileParser.finish();
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
