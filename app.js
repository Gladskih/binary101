"use strict";

import { nowIsoString, formatHumanSize } from "./binary-utils.js";
import { computeHashForFile, copyToClipboard } from "./hash.js";
import { detectBinaryType, parseForUi } from "./analyzers/index.js";
import { renderPe, renderJpeg, renderElf, renderGif } from "./renderers/index.js";
import { renderPe, renderJpeg, renderElf, renderPng } from "./renderers/index.js";
import { escapeHtml } from "./html-utils.js";

const getElement = id => document.getElementById(id);

const dropZoneElement = getElement("dropZone");
const fileInputElement = getElement("fileInput");
const statusMessageElement = getElement("statusMessage");

const fileInfoCardElement = getElement("fileInfoCard");

const fileNameTopElement = getElement("fileOriginalName");
const fileSizeTopElement = getElement("fileSizeDisplay");
const fileKindTopElement = getElement("fileKindDisplay");

const fileNameDetailElement = getElement("fileNameDetail");
const fileSizeDetailElement = getElement("fileSizeDetail");
const fileTimestampDetailElement = getElement("fileTimestampDetail");
const fileSourceDetailElement = getElement("fileSourceDetail");
const fileBinaryTypeDetailElement = getElement("fileBinaryTypeDetail");
const fileMimeTypeDetailElement = getElement("fileMimeTypeDetail");

const peDetailsTermElement = getElement("peDetailsTerm");
const peDetailsValueElement = getElement("peDetailsValue");

const sha256ValueElement = getElement("sha256Value");
const sha512ValueElement = getElement("sha512Value");
const sha256ButtonElement = getElement("sha256ComputeButton");
const sha512ButtonElement = getElement("sha512ComputeButton");
const sha256CopyButtonElement = getElement("sha256CopyButton");
const sha512CopyButtonElement = getElement("sha512CopyButton");

let currentFile = null;
let currentPreviewUrl = null;
let currentTypeLabel = "";

const setStatusMessage = message => {
  statusMessageElement.textContent = message || "";
};

const clearStatusMessage = () => {
  statusMessageElement.textContent = "";
};

function clearPreviewUrl() {
  if (currentPreviewUrl) {
    URL.revokeObjectURL(currentPreviewUrl);
    currentPreviewUrl = null;
  }
}

function buildImagePreviewHtml() {
  clearPreviewUrl();
  if (!currentFile) return "";
  const mime = (currentFile.type || "").toLowerCase();
  const label = (currentTypeLabel || "").toLowerCase();
  const looksLikeImage =
    mime.startsWith("image/") ||
    label.includes("image") ||
    label.includes("icon");
  if (!looksLikeImage) return "";
  currentPreviewUrl = URL.createObjectURL(currentFile);
  const altText = currentFile.name ? `Preview of ${currentFile.name}` : "Image preview";
  return `<div class="jpegPreview"><img src="${currentPreviewUrl}" alt="${escapeHtml(
    altText
  )}" /></div>`;
}

function renderAnalysisIntoUi(analyzerName, parsedResult) {
  const previewHtml = buildImagePreviewHtml();

  if (analyzerName === "pe" && parsedResult) {
    peDetailsTermElement.textContent = "PE/COFF details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderPe(parsedResult);
    return;
  }

  if (analyzerName === "elf" && parsedResult) {
    peDetailsTermElement.textContent = "ELF details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderElf(parsedResult);
    return;
  }

  if (analyzerName === "jpeg" && parsedResult) {
    peDetailsTermElement.textContent = "JPEG details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = previewHtml + renderJpeg(parsedResult);
    return;
  }

  if (analyzerName === "gif" && parsedResult) {
    peDetailsTermElement.textContent = "GIF details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = previewHtml + renderGif(parsedResult);
    return;
  }
  if (analyzerName === "png" && parsedResult) {
    peDetailsTermElement.textContent = "PNG details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = previewHtml + renderPng(parsedResult);
    return;
  }

  if (previewHtml) {
    peDetailsTermElement.textContent = "Image preview";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = previewHtml;
    return;
  }

  peDetailsTermElement.hidden = true;
  peDetailsValueElement.hidden = true;
  peDetailsValueElement.innerHTML = "";
}

function resetHashDisplay() {
  sha256ValueElement.textContent = "";
  sha512ValueElement.textContent = "";
  sha256CopyButtonElement.hidden = true;
  sha512CopyButtonElement.hidden = true;
  sha256ButtonElement.hidden = false;
  sha512ButtonElement.hidden = false;
  sha256ButtonElement.disabled = false;
  sha512ButtonElement.disabled = false;
  sha256ButtonElement.textContent = "Compute SHA-256";
  sha512ButtonElement.textContent = "Compute SHA-512";
}

async function showFileInfo(file, sourceDescription) {
  currentFile = file;
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

  const { analyzer, parsed } = await parseForUi(file);
  renderAnalysisIntoUi(analyzer, parsed);

  resetHashDisplay();
  fileInfoCardElement.hidden = false;
  clearStatusMessage();
}

const handleSelectedFiles = files => {
  if (!files || files.length === 0) {
    setStatusMessage("No file selected.");
    return;
  }
  if (files.length > 1) {
    setStatusMessage("Multiple files are not supported yet.");
    return;
  }
  showFileInfo(files[0], "File selection");
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
      const dataTransfer = event.dataTransfer;
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

window.addEventListener("paste", async event => {
  const clipboardData = event.clipboardData;
  if (!clipboardData) {
    setStatusMessage("Paste: clipboard not available.");
    return;
  }
  const files = [...(clipboardData.files || [])];
  if (files.length === 1) {
    showFileInfo(files[0], "Paste (file)");
    return;
  }
  const textItems = [...(clipboardData.items || [])].filter(
    item => item.kind === "string"
  );
  if (textItems.length !== 1) {
    setStatusMessage("Paste: unsupported clipboard payload.");
    return;
  }
  const text = await new Promise(resolve => textItems[0].getAsString(resolve));
  if (typeof text !== "string" || text.length === 0) {
    setStatusMessage("Paste: empty text.");
    return;
  }
  const syntheticFile = new File([text], "clipboard.bin", {
    type: "application/octet-stream"
  });
  showFileInfo(syntheticFile, "Paste (clipboard data)");
});

async function computeAndDisplayHash(algorithmName, valueElement, buttonElement, copyButtonElement) {
  if (!currentFile) {
    valueElement.textContent = "No file selected.";
    return;
  }
  buttonElement.disabled = true;
  buttonElement.textContent = "Working...";
  try {
    const hashHex = await computeHashForFile(currentFile, algorithmName);
    valueElement.textContent = hashHex;
    copyButtonElement.hidden = false;
    buttonElement.hidden = true;
    clearStatusMessage();
  } catch (error) {
    const namePart = error && error.name ? `${error.name}: ` : "";
    valueElement.textContent = `Hash failed: ${namePart}${String(error)}`;
    buttonElement.disabled = false;
    buttonElement.textContent = "Retry";
    copyButtonElement.hidden = true;
  }
}

sha256ButtonElement.addEventListener("click", () =>
  computeAndDisplayHash("SHA-256", sha256ValueElement, sha256ButtonElement, sha256CopyButtonElement)
);

sha512ButtonElement.addEventListener("click", () =>
  computeAndDisplayHash("SHA-512", sha512ValueElement, sha512ButtonElement, sha512CopyButtonElement)
);

sha256CopyButtonElement.addEventListener("click", async () => {
  const text = sha256ValueElement.textContent || "";
  const copied = await copyToClipboard(text);
  setStatusMessage(copied ? "SHA-256 copied." : "Clipboard copy failed.");
});

sha512CopyButtonElement.addEventListener("click", async () => {
  const text = sha512ValueElement.textContent || "";
  const copied = await copyToClipboard(text);
  setStatusMessage(copied ? "SHA-512 copied." : "Clipboard copy failed.");
});
