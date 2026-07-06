"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { renderMachO } from "../renderers/macho/index.js";
import {
  renderPe,
  renderCoff,
  renderJpeg,
  renderElf,
  renderGif,
  renderPng,
  renderBmp,
  renderTga,
  renderPdf,
  renderZip,
  renderWebp,
  renderWebm,
  renderMkv,
  renderFb2,
  renderMp3,
  renderFlac,
  renderMp4,
  renderSevenZip,
  renderTar,
  renderGzip,
  renderRar,
  renderIso9660,
  renderMz,
  renderLnk,
  renderWav,
  renderAvi,
  renderAni,
  renderSqlite,
  renderAsf,
  renderMpegPs,
  renderPcap,
  renderPcapNg
} from "../renderers/index.js";
import type { PreviewRender } from "./preview.js";

type RenderContext = {
  buildPreview: () => PreviewRender | null;
  attachGuards: (preview: PreviewRender | null) => void;
  termElement: HTMLElement;
  valueElement: HTMLElement;
};

type AnalysisPresenter = (term: string, valueHtml: string, guardPreview?: PreviewRender | null) => void;

const renderExecutableAnalysis = (
  result: ParseForUiResult,
  show: AnalysisPresenter
): boolean => {
  switch (result.analyzer) {
    case "coff":
      show("COFF object details", renderCoff(result.parsed));
      return true;
    case "pe":
      show("PE/COFF details", renderPe(result.parsed));
      return true;
    case "mz":
      show("MS-DOS MZ details", renderMz(result.parsed));
      return true;
    case "elf":
      show("ELF details", renderElf(result.parsed));
      return true;
    case "macho":
      show("Mach-O details", renderMachO(result.parsed));
      return true;
    default:
      return false;
  }
};

const renderArchiveAnalysis = (
  result: ParseForUiResult,
  show: AnalysisPresenter
): boolean => {
  switch (result.analyzer) {
    case "zip":
      show("ZIP details", renderZip(result.parsed));
      return true;
    case "sevenZip":
      show("7z details", renderSevenZip(result.parsed));
      return true;
    case "tar":
      show("TAR details", renderTar(result.parsed));
      return true;
    case "iso9660":
      show("ISO-9660 details", renderIso9660(result.parsed));
      return true;
    case "gzip":
      show("gzip details", renderGzip(result.parsed));
      return true;
    case "rar":
      show("RAR details", renderRar(result.parsed));
      return true;
    default:
      return false;
  }
};

const renderImageAnalysis = (
  result: ParseForUiResult,
  imagePreviewHtml: string,
  show: AnalysisPresenter
): boolean => {
  switch (result.analyzer) {
    case "jpeg":
      show("JPEG details", imagePreviewHtml + renderJpeg(result.parsed));
      return true;
    case "gif":
      show("GIF details", imagePreviewHtml + renderGif(result.parsed));
      return true;
    case "png":
      show("PNG details", imagePreviewHtml + renderPng(result.parsed));
      return true;
    case "bmp":
      show("BMP details", imagePreviewHtml + renderBmp(result.parsed));
      return true;
    case "tga":
      show("TGA details", renderTga(result.parsed));
      return true;
    case "webp":
      show("WebP details", imagePreviewHtml + renderWebp(result.parsed));
      return true;
    case "ani":
      show("ANI details", imagePreviewHtml + renderAni(result.parsed));
      return true;
    default:
      return false;
  }
};

const renderMediaAnalysis = (
  result: ParseForUiResult,
  preview: PreviewRender | null,
  videoPreviewHtml: string,
  mediaPreviewHtml: string,
  show: AnalysisPresenter
): boolean => {
  switch (result.analyzer) {
    case "webm":
      show("WebM details", videoPreviewHtml + renderWebm(result.parsed), preview);
      return true;
    case "mkv":
      show("Matroska (MKV) details", videoPreviewHtml + renderMkv(result.parsed), preview);
      return true;
    case "mp4":
      show("MP4 details", videoPreviewHtml + renderMp4(result.parsed), preview);
      return true;
    case "mpegps":
      show("MPEG Program Stream details", videoPreviewHtml + renderMpegPs(result.parsed), preview);
      return true;
    case "avi":
      show("AVI details", videoPreviewHtml + renderAvi(result.parsed), preview);
      return true;
    case "asf":
      show("ASF details", mediaPreviewHtml + renderAsf(result.parsed), preview);
      return true;
    default:
      return false;
  }
};

const renderDocumentAndAudioAnalysis = (
  result: ParseForUiResult,
  audioPreviewHtml: string,
  show: AnalysisPresenter
): boolean => {
  switch (result.analyzer) {
    case "sqlite":
      show("SQLite details", renderSqlite(result.parsed));
      return true;
    case "fb2":
      show("FB2 details", renderFb2(result.parsed));
      return true;
    case "lnk":
      show("Windows shortcut details", renderLnk(result.parsed));
      return true;
    case "pcap":
      show("PCAP details", renderPcap(result.parsed));
      return true;
    case "pcapng":
      show("PCAP-NG details", renderPcapNg(result.parsed));
      return true;
    case "pdf":
      show("PDF details", renderPdf(result.parsed));
      return true;
    case "mp3":
      show("MP3 details", audioPreviewHtml + renderMp3(result.parsed));
      return true;
    case "flac":
      show("FLAC details", audioPreviewHtml + renderFlac(result.parsed));
      return true;
    case "wav":
      show("WAV details", audioPreviewHtml + renderWav(result.parsed));
      return true;
    default:
      return false;
  }
};

const renderKnownAnalysis = (
  result: ParseForUiResult,
  preview: PreviewRender | null,
  show: AnalysisPresenter
): boolean => {
  const imagePreviewHtml = preview?.kind === "image" ? preview.html : "";
  const audioPreviewHtml = preview?.kind === "audio" ? preview.html : "";
  const videoPreviewHtml = preview?.kind === "video" ? preview.html : "";
  const mediaPreviewHtml =
    preview?.kind === "video" || preview?.kind === "audio" ? preview.html : "";
  return (
    renderExecutableAnalysis(result, show) ||
    renderArchiveAnalysis(result, show) ||
    renderImageAnalysis(result, imagePreviewHtml, show) ||
    renderMediaAnalysis(result, preview, videoPreviewHtml, mediaPreviewHtml, show) ||
    renderDocumentAndAudioAnalysis(result, audioPreviewHtml, show)
  );
};

const renderAnalysisIntoUi = (result: ParseForUiResult, ctx: RenderContext): void => {
  const preview = ctx.buildPreview();
  const show = (term: string, valueHtml: string, guardPreview?: PreviewRender | null): void => {
    ctx.termElement.textContent = term;
    ctx.termElement.hidden = true;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = valueHtml;
    if (guardPreview) ctx.attachGuards(guardPreview);
  };

  const hide = (): void => {
    ctx.termElement.hidden = true;
    ctx.valueElement.hidden = true;
    ctx.valueElement.innerHTML = "";
  };

  if (renderKnownAnalysis(result, preview, show)) return;
  if (preview) {
    const label =
      preview.kind === "video"
        ? "Video preview"
        : preview.kind === "audio"
          ? "Audio preview"
          : "Image preview";
    show(label, preview.html, preview);
    return;
  }

  hide();
};

export { renderAnalysisIntoUi };
