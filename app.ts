"use strict";

import { nowIsoString, formatHumanSize } from "./binary-utils.js";
import { detectBinaryType, parseForUi, type ParseForUiResult } from "./analyzers/index.js";
import { renderAnalysisIntoUi as renderParsedResult } from "./ui/render-analysis.js";
import { attachPreviewGuards, buildPreviewHtml } from "./ui/preview.js";
import { computeAndDisplayHash, copyHashToClipboard, resetHashDisplay } from "./ui/hash-controls.js";
import { createZipEntryClickHandler } from "./ui/zip-actions.js";

const getElement = (id: string) => document.getElementById(id)!;

const dropZoneElement = getElement("dropZone") as HTMLElement;
const fileInputElement = getElement("fileInput") as HTMLInputElement;
const statusMessageElement = getElement("statusMessage") as HTMLElement;

const fileInfoCardElement = getElement("fileInfoCard") as HTMLElement;

const fileNameTopElement = getElement("fileOriginalName") as HTMLElement;
const fileSizeTopElement = getElement("fileSizeDisplay") as HTMLElement;
const fileKindTopElement = getElement("fileKindDisplay") as HTMLElement;

const fileNameDetailElement = getElement("fileNameDetail") as HTMLElement;
const fileSizeDetailElement = getElement("fileSizeDetail") as HTMLElement;
const fileTimestampDetailElement = getElement("fileTimestampDetail") as HTMLElement;
const fileSourceDetailElement = getElement("fileSourceDetail") as HTMLElement;
const fileBinaryTypeDetailElement = getElement("fileBinaryTypeDetail") as HTMLElement;
const fileMimeTypeDetailElement = getElement("fileMimeTypeDetail") as HTMLElement;

const peDetailsTermElement = getElement("peDetailsTerm") as HTMLElement;
const peDetailsValueElement = getElement("peDetailsValue") as HTMLElement;

const sha256ValueElement = getElement("sha256Value") as HTMLElement;
const sha512ValueElement = getElement("sha512Value") as HTMLElement;
const sha256ButtonElement = getElement("sha256ComputeButton") as HTMLButtonElement;
const sha512ButtonElement = getElement("sha512ComputeButton") as HTMLButtonElement;
const sha256CopyButtonElement = getElement("sha256CopyButton") as HTMLButtonElement;
const sha512CopyButtonElement = getElement("sha512CopyButton") as HTMLButtonElement;
const sha256Controls = {
  valueElement: sha256ValueElement,
  buttonElement: sha256ButtonElement,
  copyButtonElement: sha256CopyButtonElement
};
const sha512Controls = {
  valueElement: sha512ValueElement,
  buttonElement: sha512ButtonElement,
  copyButtonElement: sha512CopyButtonElement
};

let currentFile: File | null = null;
let currentPreviewUrl: string | null = null;
let currentTypeLabel = "";
let currentParseResult: ParseForUiResult = { analyzer: null, parsed: null };

const setPreviewUrl = (url: string | null): void => {
  if (currentPreviewUrl) {
    URL.revokeObjectURL(currentPreviewUrl);
  }
  currentPreviewUrl = url;
};

const setStatusMessage = (message: string | null | undefined): void => {
  statusMessageElement.textContent = message || "";
};

const clearStatusMessage = () => {
  statusMessageElement.textContent = "";
};

const clearPreviewUrl = (): void => {
  setPreviewUrl(null);
};

const renderResult = (result: ParseForUiResult): void => {
  renderParsedResult(result, {
    buildPreview: () =>
      buildPreviewHtml({ file: currentFile, typeLabel: currentTypeLabel, setPreviewUrl }),
    attachGuards: preview => attachPreviewGuards(preview, peDetailsValueElement, setStatusMessage),
    termElement: peDetailsTermElement,
    valueElement: peDetailsValueElement
  });
};

const zipClickHandler = createZipEntryClickHandler({
  getParseResult: () => currentParseResult,
  getFile: () => currentFile,
  setStatusMessage
});

peDetailsValueElement.addEventListener("click", event => {
  void zipClickHandler(event);
});

async function showFileInfo(file: File, sourceDescription: string): Promise<void> {
  currentFile = file;
  currentParseResult = { analyzer: null, parsed: null };
  try {
    const typeLabel = await detectBinaryType(file);
    currentTypeLabel = typeLabel || "";
    const timestampIso = nowIsoString();
    const sizeText = formatHumanSize(file.size);
    const mimeType =
      typeof file.type === "string" && file.type.length > 0
        ? file.type
        : "Not provided by browser";

    fileNameTopElement.textContent = file.name || "";
    fileSizeTopElement.textContent = sizeText;
    fileKindTopElement.textContent = typeLabel;

    fileNameDetailElement.textContent = file.name || "";
    fileSizeDetailElement.textContent = sizeText;
    fileTimestampDetailElement.textContent = timestampIso;
    fileSourceDetailElement.textContent = sourceDescription;
    fileBinaryTypeDetailElement.textContent = typeLabel;
    fileMimeTypeDetailElement.textContent = mimeType;

    const parsedResult = await parseForUi(file);
    currentParseResult = parsedResult;
    renderResult(parsedResult);

    resetHashDisplay(sha256Controls, sha512Controls);
    fileInfoCardElement.hidden = false;
    clearStatusMessage();
  } catch (error) {
    currentTypeLabel = "";
    clearPreviewUrl();
    setStatusMessage(
      `Unable to read file: ${error instanceof Error && error.message ? error.message : String(error)}`
    );
    peDetailsTermElement.hidden = true;
    peDetailsValueElement.hidden = true;
    peDetailsValueElement.innerHTML = "";
  }
}

const handleSelectedFiles = (files: FileList | null): void => {
  if (!files || files.length === 0) {
    setStatusMessage("No file selected.");
    return;
  }
  if (files.length > 1) {
    setStatusMessage("Multiple files are not supported yet.");
    return;
  }
  const first = files.item(0);
  if (!first) {
    setStatusMessage("No file selected.");
    return;
  }
  void showFileInfo(first, "File selection");
};

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
        handleSelectedFiles(dataTransfer.files);
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
  const files = clipboardData.files ? Array.from(clipboardData.files) : [];
  if (files.length === 1) {
    const [file] = files;
    if (file) {
      await showFileInfo(file, "Paste (file)");
    }
    return;
  }
  const textItems = (clipboardData.items ? Array.from(clipboardData.items) : []).filter(
    item => item.kind === "string"
  );
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
  const syntheticFile = new File([text], "clipboard.bin", {
    type: "application/octet-stream"
  });
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
