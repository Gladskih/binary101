"use strict";

import { escapeHtml } from "../html-utils.js";
import { choosePreviewForFile } from "../media-preview.js";

type PreviewRender = {
  kind: "image" | "video" | "audio";
  html: string;
};

type PreviewContext = {
  file: File | null;
  typeLabel: string;
  setPreviewUrl: (url: string | null) => void;
};

const buildPreviewHtml = ({ file, typeLabel, setPreviewUrl }: PreviewContext): PreviewRender | null => {
  setPreviewUrl(null);
  if (!file) return null;
  const previewCandidate = choosePreviewForFile({
    fileName: file.name || "",
    mimeType: file.type || "",
    typeLabel: typeLabel || ""
  });
  if (!previewCandidate) return null;
  const previewUrl = URL.createObjectURL(file);
  setPreviewUrl(previewUrl);
  if (previewCandidate.kind === "image") {
    const altText = file.name ? `Preview of ${file.name}` : "Image preview";
    return {
      kind: "image",
      html: `<div class="jpegPreview"><img src="${previewUrl}" alt="${escapeHtml(
        altText
      )}" /></div>`
    };
  }
  if (previewCandidate.kind === "audio") {
    return {
      kind: "audio",
      html: [
        '<div class="audioPreview">',
        `<audio controls preload="metadata" src="${previewUrl}"${previewCandidate.mimeType ? ` type="${previewCandidate.mimeType}"` : ""}></audio>`,
        "</div>"
      ].join("")
    };
  }
  const fallbackText = file.name
    ? `Your browser cannot play this video inline: ${file.name}.`
    : "Your browser cannot play this video inline.";
  return {
    kind: "video",
    html: [
      '<div class="videoPreview">',
      '<video controls preload="metadata" playsinline>',
      `<source src="${previewUrl}"${previewCandidate.mimeType ? ` type="${previewCandidate.mimeType}"` : ""}>`,
      escapeHtml(fallbackText),
      "</video>",
      "</div>"
    ].join("")
  };
};

const attachPreviewGuards = (
  preview: PreviewRender | null,
  container: HTMLElement,
  setStatusMessage: (message: string | null | undefined) => void
): void => {
  if (!preview) return;
  if (preview.kind === "video") {
    const videoElement = container.querySelector(".videoPreview video") as HTMLVideoElement | null;
    if (videoElement) {
      const removePreview = (): void => {
        const wrapper = videoElement.closest(".videoPreview") as HTMLElement | null;
        if (wrapper?.parentElement) wrapper.parentElement.removeChild(wrapper);
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
    const audioElement = container.querySelector(".audioPreview audio") as HTMLAudioElement | null;
    if (audioElement) {
      const removePreview = (): void => {
        const wrapper = audioElement.closest(".audioPreview") as HTMLElement | null;
        if (wrapper?.parentElement) wrapper.parentElement.removeChild(wrapper);
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
};

export type { PreviewRender };
export { attachPreviewGuards, buildPreviewHtml };
