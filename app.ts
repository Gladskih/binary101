/* eslint-disable max-lines */
"use strict";

import { nowIsoString, formatHumanSize, bufferToHex } from "./binary-utils.js";
import { detectBinaryType, parseForUi, type AnalyzerName, type ParseForUiResult } from "./analyzers/index.js";
import {
  renderPe,
  renderJpeg,
  renderElf,
  renderGif,
  renderPng,
  renderPdf,
  renderZip,
  renderWebp,
  renderFb2,
  renderMp3,
  renderSevenZip,
  renderTar,
  renderRar,
  renderMz,
  renderLnk,
} from "./renderers/index.js";
import { escapeHtml } from "./html-utils.js";

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

let currentFile: File | null = null;
let currentPreviewUrl: string | null = null;
let currentTypeLabel = "";
let currentAnalyzerName: AnalyzerName | null = null;
let currentParsedResult: ParseForUiResult["parsed"] | null = null;

const setStatusMessage = (message: string | null | undefined): void => {
  statusMessageElement.textContent = message || "";
};

const clearStatusMessage = () => {
  statusMessageElement.textContent = "";
};

function clearPreviewUrl(): void {
  if (currentPreviewUrl) {
    URL.revokeObjectURL(currentPreviewUrl);
    currentPreviewUrl = null;
  }
}

function buildImagePreviewHtml(): string {
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

function renderAnalysisIntoUi(
  analyzerName: AnalyzerName | null,
  parsedResult: ParseForUiResult["parsed"]
): void {
  const previewHtml = buildImagePreviewHtml();

  if (analyzerName === "pe" && parsedResult) {
    peDetailsTermElement.textContent = "PE/COFF details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderPe(parsedResult);
    return;
  }

  if (analyzerName === "mz" && parsedResult) {
    peDetailsTermElement.textContent = "MS-DOS MZ details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderMz(parsedResult);
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

  if (analyzerName === "fb2" && parsedResult) {
    peDetailsTermElement.textContent = "FB2 details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderFb2(parsedResult);
    return;
  }
  if (analyzerName === "gif" && parsedResult) {
    peDetailsTermElement.textContent = "GIF details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = previewHtml + renderGif(parsedResult);
    return;
  }
  if (analyzerName === "zip" && parsedResult) {
    peDetailsTermElement.textContent = "ZIP details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderZip(parsedResult);
    return;
  }
  if (analyzerName === "sevenZip" && parsedResult) {
    peDetailsTermElement.textContent = "7z details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderSevenZip(parsedResult);
    return;
  }

  if (analyzerName === "tar" && parsedResult) {
    peDetailsTermElement.textContent = "TAR details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderTar(parsedResult);
    return;
  }

  if (analyzerName === "rar" && parsedResult) {
    peDetailsTermElement.textContent = "RAR details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderRar(parsedResult);
    return;
  }
  if (analyzerName === "lnk" && parsedResult) {
    peDetailsTermElement.textContent = "Windows shortcut details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderLnk(parsedResult);
    return;
  }
  
  if (analyzerName === "png" && parsedResult) {
    peDetailsTermElement.textContent = "PNG details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = previewHtml + renderPng(parsedResult);
    return;
  }

  if (analyzerName === "webp" && parsedResult) {
    peDetailsTermElement.textContent = "WebP details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = previewHtml + renderWebp(parsedResult);
    return;
  }

  if (analyzerName === "pdf" && parsedResult) {
    peDetailsTermElement.textContent = "PDF details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderPdf(parsedResult);
    return;
  }

  if (analyzerName === "mp3" && parsedResult) {
    peDetailsTermElement.textContent = "MP3 details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderMp3(parsedResult);
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

type ZipCentralDirectoryEntryForUi = {
  index: number;
  fileName?: string;
  dataOffset?: number | null;
  dataLength?: number | null;
  compressionMethod: number;
  extractError?: string;
};

type ZipParsedResultForUi = {
  centralDirectory?: {
    entries?: ZipCentralDirectoryEntryForUi[];
  };
};

const sanitizeDownloadName = (entry: ZipCentralDirectoryEntryForUi): string => {
  const name = typeof entry.fileName === "string" && entry.fileName.length ? entry.fileName : "entry.bin";
  const parts = name.split(/[\\/]/);
  const last = parts[parts.length - 1] || "entry.bin";
  return last.trim().length ? last.trim() : "entry.bin";
};

const findZipEntryByIndex = (index: number): ZipCentralDirectoryEntryForUi | null => {
  if (currentAnalyzerName !== "zip") return null;
  const parsed = currentParsedResult as ZipParsedResultForUi | null;
  const entries = parsed?.centralDirectory?.entries;
  if (!Array.isArray(entries)) return null;
  return entries.find(entry => entry.index === index) || null;
};

const sliceZipEntryBlob = (entry: ZipCentralDirectoryEntryForUi): Blob => {
  if (!currentFile) throw new Error("No file selected.");
  if (entry.dataOffset == null || entry.dataLength == null) {
    throw new Error("Entry is missing data bounds.");
  }
  return currentFile.slice(entry.dataOffset, entry.dataOffset + entry.dataLength);
};

const decompressZipEntry = async (
  entry: ZipCentralDirectoryEntryForUi,
  compressedBlob: Blob
): Promise<Blob> => {
  if (entry.compressionMethod === 0) return compressedBlob;
  if (typeof DecompressionStream !== "function") {
    throw new Error("Browser does not support DecompressionStream for deflated entries.");
  }
  const stream = compressedBlob.stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Response(stream).blob();
};

const triggerDownload = (blob: Blob, suggestedName: string): void => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = suggestedName;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

peDetailsValueElement.addEventListener("click", async event => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const buttonTarget: HTMLButtonElement | null =
    target instanceof HTMLButtonElement ? target : null;
  const indexAttr = target.getAttribute("data-zip-entry");
  if (!indexAttr) return;
  const entryIndex = Number.parseInt(indexAttr, 10);
  if (Number.isNaN(entryIndex)) return;
  const entry = findZipEntryByIndex(entryIndex);
  if (!entry) {
    setStatusMessage("ZIP entry not found.");
    return;
  }
  if (entry.extractError) {
    setStatusMessage(entry.extractError);
    return;
  }
  if (!currentFile) {
    setStatusMessage("No file selected.");
    return;
  }
  if (entry.compressionMethod === 8 && typeof DecompressionStream !== "function") {
    setStatusMessage("Browser does not support DecompressionStream; cannot decompress this entry.");
    return;
  }
  const originalText = target.textContent;
  if (buttonTarget) {
    buttonTarget.disabled = true;
    buttonTarget.textContent = entry.compressionMethod === 8 ? "Decompressing..." : "Preparing...";
  }
  try {
    const compressedBlob = await sliceZipEntryBlob(entry);
    const blob = await decompressZipEntry(entry, compressedBlob);
    triggerDownload(blob, sanitizeDownloadName(entry));
    clearStatusMessage();
  } catch (error) {
    const message = error instanceof Error && error.message ? error.message : String(error);
    setStatusMessage(`Extract failed: ${message}`);
  } finally {
    if (buttonTarget) {
      buttonTarget.disabled = false;
      buttonTarget.textContent = originalText || "Extract";
    }
  }
});

function resetHashDisplay(): void {
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

async function showFileInfo(file: File, sourceDescription: string): Promise<void> {
  currentFile = file;
  currentAnalyzerName = null;
  currentParsedResult = null;
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
  currentAnalyzerName = analyzer;
  currentParsedResult = parsed;
  renderAnalysisIntoUi(analyzer, parsed);

  resetHashDisplay();
  fileInfoCardElement.hidden = false;
  clearStatusMessage();
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

window.addEventListener("paste", async event => {
  const clipboardData = event.clipboardData;
  if (!clipboardData) {
    setStatusMessage("Paste: clipboard not available.");
    return;
  }
  const files = clipboardData.files ? Array.from(clipboardData.files) : [];
  if (files.length === 1) {
    showFileInfo(files[0], "Paste (file)");
    return;
  }
  const textItems = (clipboardData.items ? Array.from(clipboardData.items) : []).filter(
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

async function computeAndDisplayHash(
  algorithmName: AlgorithmIdentifier,
  valueElement: HTMLElement,
  buttonElement: HTMLButtonElement,
  copyButtonElement: HTMLButtonElement
): Promise<void> {
  if (!currentFile) {
    valueElement.textContent = "No file selected.";
    return;
  }
  buttonElement.disabled = true;
  buttonElement.textContent = "Working...";
  try {
    valueElement.textContent = bufferToHex(
      await crypto.subtle.digest(algorithmName, await currentFile.arrayBuffer())
    );
    copyButtonElement.hidden = false;
    buttonElement.hidden = true;
    clearStatusMessage();
  } catch (error) {
    const namePart = error instanceof Error && error.name ? `${error.name}: ` : "";
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
  try {
    await navigator.clipboard.writeText(text);
    setStatusMessage("SHA-256 copied.");
  } catch {
    setStatusMessage("Clipboard copy failed.");
  }
});

sha512CopyButtonElement.addEventListener("click", async () => {
  const text = sha512ValueElement.textContent || "";
  try {
    await navigator.clipboard.writeText(text);
    setStatusMessage("SHA-512 copied.");
  } catch {
    setStatusMessage("Clipboard copy failed.");
  }
});
