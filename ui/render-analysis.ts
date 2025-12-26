"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
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
  renderFlac,
  renderMp4,
  renderSevenZip,
  renderTar,
  renderGzip,
  renderRar,
  renderMz,
  renderLnk,
  renderWav,
  renderAvi,
  renderAni,
  renderSqlite,
  renderAsf,
  renderMpegPs,
  renderPcap
} from "../renderers/index.js";
import type { PreviewRender } from "./preview.js";

type RenderContext = {
  buildPreview: () => PreviewRender | null;
  attachGuards: (preview: PreviewRender | null) => void;
  termElement: HTMLElement;
  valueElement: HTMLElement;
};

const renderAnalysisIntoUi = (result: ParseForUiResult, ctx: RenderContext): void => {
  const preview = ctx.buildPreview();
  const imagePreviewHtml = preview?.kind === "image" ? preview.html : "";
  const audioPreviewHtml = preview?.kind === "audio" ? preview.html : "";

  if (result.analyzer === "pe") {
    ctx.termElement.textContent = "PE/COFF details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderPe(result.parsed);
    return;
  }

  if (result.analyzer === "mz") {
    ctx.termElement.textContent = "MS-DOS MZ details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderMz(result.parsed);
    return;
  }

  if (result.analyzer === "elf") {
    ctx.termElement.textContent = "ELF details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderElf(result.parsed);
    return;
  }

  if (result.analyzer === "jpeg") {
    ctx.termElement.textContent = "JPEG details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = imagePreviewHtml + renderJpeg(result.parsed);
    return;
  }
  if (result.analyzer === "sqlite") {
    ctx.termElement.textContent = "SQLite details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderSqlite(result.parsed);
    return;
  }

  if (result.analyzer === "fb2") {
    ctx.termElement.textContent = "FB2 details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderFb2(result.parsed);
    return;
  }

  if (result.analyzer === "gif") {
    ctx.termElement.textContent = "GIF details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = imagePreviewHtml + renderGif(result.parsed);
    return;
  }
  if (result.analyzer === "zip") {
    ctx.termElement.textContent = "ZIP details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderZip(result.parsed);
    return;
  }
  if (result.analyzer === "sevenZip") {
    ctx.termElement.textContent = "7z details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderSevenZip(result.parsed);
    return;
  }

  if (result.analyzer === "tar") {
    ctx.termElement.textContent = "TAR details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderTar(result.parsed);
    return;
  }

  if (result.analyzer === "gzip") {
    ctx.termElement.textContent = "gzip details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderGzip(result.parsed);
    return;
  }

  if (result.analyzer === "rar") {
    ctx.termElement.textContent = "RAR details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderRar(result.parsed);
    return;
  }
  if (result.analyzer === "lnk") {
    ctx.termElement.textContent = "Windows shortcut details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderLnk(result.parsed);
    return;
  }

  if (result.analyzer === "png") {
    ctx.termElement.textContent = "PNG details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = imagePreviewHtml + renderPng(result.parsed);
    return;
  }

  if (result.analyzer === "webp") {
    ctx.termElement.textContent = "WebP details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = imagePreviewHtml + renderWebp(result.parsed);
    return;
  }

  if (result.analyzer === "ani") {
    ctx.termElement.textContent = "ANI details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = imagePreviewHtml + renderAni(result.parsed);
    return;
  }

  if (result.analyzer === "webm") {
    ctx.termElement.textContent = "WebM details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    const videoPreviewHtml = preview?.kind === "video" ? preview.html : "";
    ctx.valueElement.innerHTML = videoPreviewHtml + renderWebm(result.parsed);
    ctx.attachGuards(preview);
    return;
  }

  if (result.analyzer === "mp4") {
    ctx.termElement.textContent = "MP4 details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    const videoPreviewHtml = preview?.kind === "video" ? preview.html : "";
    ctx.valueElement.innerHTML = videoPreviewHtml + renderMp4(result.parsed);
    ctx.attachGuards(preview);
    return;
  }

  if (result.analyzer === "mpegps") {
    ctx.termElement.textContent = "MPEG Program Stream details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    const videoPreviewHtml = preview?.kind === "video" ? preview.html : "";
    ctx.valueElement.innerHTML = videoPreviewHtml + renderMpegPs(result.parsed);
    ctx.attachGuards(preview);
    return;
  }

  if (result.analyzer === "avi") {
    ctx.termElement.textContent = "AVI details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    const videoPreviewHtml = preview?.kind === "video" ? preview.html : "";
    ctx.valueElement.innerHTML = videoPreviewHtml + renderAvi(result.parsed);
    ctx.attachGuards(preview);
    return;
  }

  if (result.analyzer === "asf") {
    ctx.termElement.textContent = "ASF details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    const mediaPreviewHtml =
      preview?.kind === "video" || preview?.kind === "audio" ? preview.html : "";
    ctx.valueElement.innerHTML = mediaPreviewHtml + renderAsf(result.parsed);
    ctx.attachGuards(preview);
    return;
  }

  if (result.analyzer === "pcap") {
    ctx.termElement.textContent = "PCAP details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderPcap(result.parsed);
    return;
  }

  if (result.analyzer === "pdf") {
    ctx.termElement.textContent = "PDF details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = renderPdf(result.parsed);
    return;
  }

  if (result.analyzer === "mp3") {
    ctx.termElement.textContent = "MP3 details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = audioPreviewHtml + renderMp3(result.parsed);
    return;
  }

  if (result.analyzer === "flac") {
    ctx.termElement.textContent = "FLAC details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = audioPreviewHtml + renderFlac(result.parsed);
    return;
  }

  if (result.analyzer === "wav") {
    ctx.termElement.textContent = "WAV details";
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = audioPreviewHtml + renderWav(result.parsed);
    return;
  }

  if (preview) {
    const label =
      preview.kind === "video"
        ? "Video preview"
        : preview.kind === "audio"
          ? "Audio preview"
          : "Image preview";
    ctx.termElement.textContent = label;
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = preview.html;
    ctx.attachGuards(preview);
    return;
  }

  ctx.termElement.hidden = true;
  ctx.valueElement.hidden = true;
  ctx.valueElement.innerHTML = "";
};

export { renderAnalysisIntoUi };
