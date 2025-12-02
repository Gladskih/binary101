/* eslint-disable max-lines */
"use strict";

import { nowIsoString, formatHumanSize, bufferToHex } from "./binary-utils.js";
import { detectBinaryType, parseForUi, type ParseForUiResult } from "./analyzers/index.js";
import {
  renderPe,
  renderJpeg,
  renderElf,
  renderGif,
  renderPng,
  renderPdf,
  renderZip,
  renderWebp,
  renderWebm,
  renderFb2,
  renderMp3,
  renderMp4,
  renderSevenZip,
  renderTar,
  renderRar,
  renderMz,
  renderLnk,
} from "./renderers/index.js";
import { escapeHtml } from "./html-utils.js";
import { choosePreviewForFile } from "./media-preview.js";
import type { ZipCentralDirectoryEntry } from "./analyzers/zip/index.js";

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
let currentParseResult: ParseForUiResult = { analyzer: null, parsed: null };

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

type PreviewRender = {
  kind: "image" | "video" | "audio";
  html: string;
};

function attachPreviewGuards(preview: PreviewRender | null): void {
  if (!preview) return;
  if (preview.kind === "video") {
    const videoElement = peDetailsValueElement.querySelector(".videoPreview video") as HTMLVideoElement | null;
    if (videoElement) {
      const removePreview = (): void => {
        const container = videoElement.closest(".videoPreview") as HTMLElement | null;
        if (container?.parentElement) container.parentElement.removeChild(container);
        setStatusMessage("Preview not shown: browser cannot play this video format inline.");
      };
      const onSuccess = (): void => {
        videoElement.removeEventListener("error", removePreview);
        videoElement.removeEventListener("stalled", removePreview);
        videoElement.removeEventListener("abort", removePreview);
      };
      videoElement.addEventListener("loadedmetadata", onSuccess, { once: true });
      ["error", "stalled", "abort"].forEach(eventName => {
        videoElement.addEventListener(eventName, removePreview, { once: true });
      });
    }
  } else if (preview.kind === "audio") {
    const audioElement = peDetailsValueElement.querySelector(".audioPreview audio") as HTMLAudioElement | null;
    if (audioElement) {
      const removePreview = (): void => {
        const container = audioElement.closest(".audioPreview") as HTMLElement | null;
        if (container?.parentElement) container.parentElement.removeChild(container);
        setStatusMessage("Preview not shown: browser cannot play this audio format inline.");
      };
      const onSuccess = (): void => {
        audioElement.removeEventListener("error", removePreview);
        audioElement.removeEventListener("stalled", removePreview);
        audioElement.removeEventListener("abort", removePreview);
      };
      audioElement.addEventListener("loadedmetadata", onSuccess, { once: true });
      ["error", "stalled", "abort"].forEach(eventName => {
        audioElement.addEventListener(eventName, removePreview, { once: true });
      });
    }
  }
}

function buildPreviewHtml(): PreviewRender | null {
  clearPreviewUrl();
  if (!currentFile) return null;
  const previewCandidate = choosePreviewForFile({
    fileName: currentFile.name || "",
    mimeType: currentFile.type || "",
    typeLabel: currentTypeLabel || ""
  });
  if (!previewCandidate) return null;
  currentPreviewUrl = URL.createObjectURL(currentFile);
  if (previewCandidate.kind === "image") {
    const altText = currentFile.name ? `Preview of ${currentFile.name}` : "Image preview";
    return {
      kind: "image",
      html: `<div class="jpegPreview"><img src="${currentPreviewUrl}" alt="${escapeHtml(
        altText
      )}" /></div>`
    };
  }
  if (previewCandidate.kind === "audio") {
    return {
      kind: "audio",
      html: [
        '<div class="audioPreview">',
        `<audio controls preload="metadata" src="${currentPreviewUrl}"${previewCandidate.mimeType ? ` type="${previewCandidate.mimeType}"` : ""}></audio>`,
        "</div>"
      ].join("")
    };
  }
  const fallbackText = currentFile.name
    ? `Your browser cannot play this video inline: ${currentFile.name}.`
    : "Your browser cannot play this video inline.";
  return {
    kind: "video",
    html: [
      '<div class="videoPreview">',
      '<video controls preload="metadata" playsinline>',
      `<source src="${currentPreviewUrl}"${previewCandidate.mimeType ? ` type="${previewCandidate.mimeType}"` : ""}>`,
      escapeHtml(fallbackText),
      "</video>",
      "</div>"
    ].join("")
  };
}

function renderAnalysisIntoUi(result: ParseForUiResult): void {
  const preview = buildPreviewHtml();
  const imagePreviewHtml = preview?.kind === "image" ? preview.html : "";
  const audioPreviewHtml = preview?.kind === "audio" ? preview.html : "";

  if (result.analyzer === "pe") {
    peDetailsTermElement.textContent = "PE/COFF details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderPe(result.parsed);
    return;
  }

  if (result.analyzer === "mz") {
    peDetailsTermElement.textContent = "MS-DOS MZ details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderMz(result.parsed);
    return;
  }

  if (result.analyzer === "elf") {
    peDetailsTermElement.textContent = "ELF details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderElf(result.parsed);
    return;
  }

  if (result.analyzer === "jpeg") {
    peDetailsTermElement.textContent = "JPEG details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = imagePreviewHtml + renderJpeg(result.parsed);
    return;
  }

  if (result.analyzer === "fb2") {
    peDetailsTermElement.textContent = "FB2 details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderFb2(result.parsed);
    return;
  }
  if (result.analyzer === "gif") {
    peDetailsTermElement.textContent = "GIF details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = imagePreviewHtml + renderGif(result.parsed);
    return;
  }
  if (result.analyzer === "zip") {
    peDetailsTermElement.textContent = "ZIP details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderZip(result.parsed);
    return;
  }
  if (result.analyzer === "sevenZip") {
    peDetailsTermElement.textContent = "7z details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderSevenZip(result.parsed);
    return;
  }

  if (result.analyzer === "tar") {
    peDetailsTermElement.textContent = "TAR details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderTar(result.parsed);
    return;
  }

  if (result.analyzer === "rar") {
    peDetailsTermElement.textContent = "RAR details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderRar(result.parsed);
    return;
  }
  if (result.analyzer === "lnk") {
    peDetailsTermElement.textContent = "Windows shortcut details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderLnk(result.parsed);
    return;
  }

  if (result.analyzer === "png") {
    peDetailsTermElement.textContent = "PNG details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = imagePreviewHtml + renderPng(result.parsed);
    return;
  }

  if (result.analyzer === "webp") {
    peDetailsTermElement.textContent = "WebP details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = imagePreviewHtml + renderWebp(result.parsed);
    return;
  }

  if (result.analyzer === "webm") {
    peDetailsTermElement.textContent = "WebM details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    const videoPreviewHtml = preview?.kind === "video" ? preview.html : "";
    peDetailsValueElement.innerHTML = videoPreviewHtml + renderWebm(result.parsed);
    attachPreviewGuards(preview);
    return;
  }

  if (result.analyzer === "mp4") {
    peDetailsTermElement.textContent = "MP4 details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    const videoPreviewHtml = preview?.kind === "video" ? preview.html : "";
    peDetailsValueElement.innerHTML = videoPreviewHtml + renderMp4(result.parsed);
    attachPreviewGuards(preview);
    return;
  }

  if (result.analyzer === "pdf") {
    peDetailsTermElement.textContent = "PDF details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = renderPdf(result.parsed);
    return;
  }

  if (result.analyzer === "mp3") {
    peDetailsTermElement.textContent = "MP3 details";
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = audioPreviewHtml + renderMp3(result.parsed);
    return;
  }

  if (preview) {
    const label =
      preview.kind === "video"
        ? "Video preview"
        : preview.kind === "audio"
          ? "Audio preview"
          : "Image preview";
    peDetailsTermElement.textContent = label;
    peDetailsTermElement.hidden = false;
    peDetailsValueElement.hidden = false;
    peDetailsValueElement.innerHTML = preview.html;
    attachPreviewGuards(preview);
    return;
  }

  peDetailsTermElement.hidden = true;
  peDetailsValueElement.hidden = true;
  peDetailsValueElement.innerHTML = "";
}

const sanitizeDownloadName = (entry: ZipCentralDirectoryEntry): string => {
  const name = typeof entry.fileName === "string" && entry.fileName.length ? entry.fileName : "entry.bin";
  const parts = name.split(/[\\/]/);
  const last = parts[parts.length - 1] || "entry.bin";
  return last.trim().length ? last.trim() : "entry.bin";
};

const findZipEntryByIndex = (index: number): ZipCentralDirectoryEntry | null => {
  if (currentParseResult.analyzer !== "zip") return null;
  const entries = currentParseResult.parsed.centralDirectory?.entries;
  if (!Array.isArray(entries)) return null;
  return entries.find(entry => entry.index === index) || null;
};

const sliceZipEntryBlob = (entry: ZipCentralDirectoryEntry): Blob => {
  if (!currentFile) throw new Error("No file selected.");
  if (entry.dataOffset == null || entry.dataLength == null) {
    throw new Error("Entry is missing data bounds.");
  }
  return currentFile.slice(entry.dataOffset, entry.dataOffset + entry.dataLength);
};

const decompressZipEntry = async (
  entry: ZipCentralDirectoryEntry,
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

const handleZipEntryClick = async (event: Event): Promise<void> => {
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
};

peDetailsValueElement.addEventListener("click", event => {
  void handleZipEntryClick(event);
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
    renderAnalysisIntoUi(parsedResult);

    resetHashDisplay();
    fileInfoCardElement.hidden = false;
    clearStatusMessage();
  } catch (error) {
    currentTypeLabel = "";
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

sha256ButtonElement.addEventListener("click", () => {
  void computeAndDisplayHash("SHA-256", sha256ValueElement, sha256ButtonElement, sha256CopyButtonElement);
});

sha512ButtonElement.addEventListener("click", () => {
  void computeAndDisplayHash("SHA-512", sha512ValueElement, sha512ButtonElement, sha512CopyButtonElement);
});

const copyHashToClipboard = async (
  valueElement: HTMLElement,
  successMessage: string
): Promise<void> => {
  const text = valueElement.textContent || "";
  try {
    await navigator.clipboard.writeText(text);
    setStatusMessage(successMessage);
  } catch {
    setStatusMessage("Clipboard copy failed.");
  }
};

sha256CopyButtonElement.addEventListener("click", () => {
  void copyHashToClipboard(sha256ValueElement, "SHA-256 copied.");
});

sha512CopyButtonElement.addEventListener("click", () => {
  void copyHashToClipboard(sha512ValueElement, "SHA-512 copied.");
});
