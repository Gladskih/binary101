"use strict";

export type PreviewKind = "image" | "video" | "audio";

export interface PreviewCandidate {
  kind: PreviewKind;
  mimeType: string | null;
}

export interface PreviewContext {
  fileName: string;
  mimeType: string;
  typeLabel: string;
}

export type CanPlayTypeFn = (mimeType: string) => string;

export type MediaCanPlayType = {
  video: CanPlayTypeFn;
  audio: CanPlayTypeFn;
};

const labelContains = (label: string, needle: string): boolean =>
  label.indexOf(needle) !== -1;

const deriveVideoMimeFromLabel = (label: string): string | null => {
  if (!label) return null;
  const mentionsIsoVideo =
    labelContains(label, "mp4") || labelContains(label, "quicktime") || labelContains(label, "iso-bmff");
  if (labelContains(label, "webm") || labelContains(label, "matroska")) return "video/webm";
  if (mentionsIsoVideo) return "video/mp4";
  if (labelContains(label, "transport stream")) return "video/mp2t";
  if (labelContains(label, "program stream")) return "video/mpeg";
  if (labelContains(label, "avi")) return "video/x-msvideo";
  if (labelContains(label, "flv")) return "video/x-flv";
  if (labelContains(label, "asf") || labelContains(label, "wmv")) return "video/x-ms-wmv";
  if (labelContains(label, "3gp")) return "video/3gpp";
  return labelContains(label, "video") ? "video/mp4" : null;
};

const looksLikeImage = (mimeType: string, typeLabel: string): boolean => {
  if (mimeType.startsWith("image/")) return true;
  if (typeLabel.indexOf("image") !== -1) return true;
  if (typeLabel.indexOf("icon") !== -1) return true;
  return false;
};

const looksLikeVideo = (mimeType: string, typeLabel: string): boolean => {
  if (mimeType.startsWith("video/")) return true;
  if (typeLabel.indexOf("video") !== -1) return true;
  if (typeLabel.indexOf("mp4") !== -1) return true;
  if (typeLabel.indexOf("quicktime") !== -1) return true;
  if (typeLabel.indexOf("matroska") !== -1) return true;
  if (typeLabel.indexOf("webm") !== -1) return true;
  if (typeLabel.indexOf("3gp") !== -1) return true;
  if (typeLabel.indexOf("avi") !== -1) return true;
  if (typeLabel.indexOf("flv") !== -1) return true;
  if (typeLabel.indexOf("asf") !== -1 || typeLabel.indexOf("wmv") !== -1) return true;
  if (typeLabel.indexOf("transport stream") !== -1) return true;
  if (typeLabel.indexOf("program stream") !== -1) return true;
  return false;
};

const looksLikeAudio = (mimeType: string, typeLabel: string): boolean => {
  if (mimeType.startsWith("audio/")) return true;
  if (typeLabel.indexOf("audio") !== -1) return true;
  if (typeLabel.indexOf("mp3") !== -1) return true;
  if (typeLabel.indexOf("mpeg audio") !== -1) return true;
  return false;
};

export const choosePreviewForFile = (context: PreviewContext): PreviewCandidate | null => {
  const mimeType = (context.mimeType || "").toLowerCase();
  const typeLabel = (context.typeLabel || "").toLowerCase();
  if (looksLikeImage(mimeType, typeLabel)) {
    return { kind: "image", mimeType: mimeType.startsWith("image/") ? mimeType : null };
  }
  if (mimeType.startsWith("image/")) return { kind: "image", mimeType };
  if (mimeType.startsWith("video/")) return { kind: "video", mimeType };
  if (mimeType.startsWith("audio/")) return { kind: "audio", mimeType };
  const videoMime = deriveVideoMimeFromLabel(typeLabel) || (looksLikeVideo(mimeType, typeLabel) ? "video/mp4" : null);
  if (videoMime) return { kind: "video", mimeType: videoMime };
  if (looksLikeAudio(mimeType, typeLabel)) return { kind: "audio", mimeType: mimeType || "audio/mpeg" };
  return null;
};

const isPlayableByCanPlayType = (
  candidate: PreviewCandidate,
  canPlayType: MediaCanPlayType
): boolean => {
  if (candidate.kind === "image") return true;
  if (!candidate.mimeType) return true;
  const probe = candidate.kind === "video" ? canPlayType.video : canPlayType.audio;
  const result = probe(candidate.mimeType);
  return typeof result === "string" && result.length > 0;
};

export const choosePlayablePreviewCandidate = (
  primary: PreviewCandidate | null,
  derivedFromLabel: PreviewCandidate | null,
  canPlayType: MediaCanPlayType | null
): PreviewCandidate | null => {
  if (!primary) return null;
  if (!canPlayType) return primary;
  if (isPlayableByCanPlayType(primary, canPlayType)) return primary;
  if (derivedFromLabel && isPlayableByCanPlayType(derivedFromLabel, canPlayType)) return derivedFromLabel;
  return null;
};
