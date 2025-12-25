"use strict";

import { escapeHtml } from "../html-utils.js";
import {
  choosePlayablePreviewCandidate,
  choosePreviewForFile,
  type MediaCanPlayType
} from "../media-preview.js";

type PreviewRender = {
  kind: "image" | "video" | "audio";
  html: string;
};

type PreviewContext = {
  file: File | null;
  typeLabel: string;
  setPreviewUrl: (url: string | null) => void;
};

const buildCanPlayTypeProbes = (): MediaCanPlayType | null => {
  if (typeof document === "undefined") return null;
  const videoProbe = document.createElement("video");
  const audioProbe = document.createElement("audio");
  return {
    video: mimeType => videoProbe.canPlayType(mimeType),
    audio: mimeType => audioProbe.canPlayType(mimeType)
  };
};

const buildPreviewHtml = ({ file, typeLabel, setPreviewUrl }: PreviewContext): PreviewRender | null => {
  setPreviewUrl(null);
  if (!file) return null;
  const context = {
    fileName: file.name || "",
    mimeType: file.type || "",
    typeLabel: typeLabel || ""
  };
  const primaryCandidate = choosePreviewForFile(context);
  if (!primaryCandidate) return null;
  const labelDerivedCandidate =
    context.mimeType && context.mimeType.length > 0
      ? choosePreviewForFile({ ...context, mimeType: "" })
      : null;
  const canPlayType = buildCanPlayTypeProbes();
  const previewCandidate = choosePlayablePreviewCandidate(
    primaryCandidate,
    labelDerivedCandidate,
    canPlayType
  );
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
        if (!videoElement.isConnected) return;
        const wrapper = videoElement.closest(".videoPreview") as HTMLElement | null;
        if (wrapper?.parentElement) wrapper.parentElement.removeChild(wrapper);
        setStatusMessage("Preview not shown: browser cannot play this video format inline.");
      };
      videoElement.addEventListener("error", removePreview, { once: true });
      const sourceElement = videoElement.querySelector("source") as HTMLSourceElement | null;
      sourceElement?.addEventListener("error", removePreview, { once: true });
    }
  } else if (preview.kind === "audio") {
    const audioElement = container.querySelector(".audioPreview audio") as HTMLAudioElement | null;
    if (audioElement) {
      const removePreview = (): void => {
        if (!audioElement.isConnected) return;
        const wrapper = audioElement.closest(".audioPreview") as HTMLElement | null;
        if (wrapper?.parentElement) wrapper.parentElement.removeChild(wrapper);
        setStatusMessage("Preview not shown: browser cannot play this audio format inline.");
      };
      audioElement.addEventListener("error", removePreview, { once: true });
    }
  }
};

export type { PreviewRender };
export { attachPreviewGuards, buildPreviewHtml };
