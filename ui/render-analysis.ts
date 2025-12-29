"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import {
  renderPe,
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
  const videoPreviewHtml = preview?.kind === "video" ? preview.html : "";
  const mediaPreviewHtml =
    preview?.kind === "video" || preview?.kind === "audio" ? preview.html : "";

  const show = (term: string, valueHtml: string, guardPreview?: PreviewRender | null): void => {
    ctx.termElement.textContent = term;
    ctx.termElement.hidden = false;
    ctx.valueElement.hidden = false;
    ctx.valueElement.innerHTML = valueHtml;
    if (guardPreview) ctx.attachGuards(guardPreview);
  };

  const hide = (): void => {
    ctx.termElement.hidden = true;
    ctx.valueElement.hidden = true;
    ctx.valueElement.innerHTML = "";
  };

  switch (result.analyzer) {
    case "pe":
      show("PE/COFF details", renderPe(result.parsed));
      return;
    case "mz":
      show("MS-DOS MZ details", renderMz(result.parsed));
      return;
    case "elf":
      show("ELF details", renderElf(result.parsed));
      return;
    case "jpeg":
      show("JPEG details", imagePreviewHtml + renderJpeg(result.parsed));
      return;
    case "sqlite":
      show("SQLite details", renderSqlite(result.parsed));
      return;
    case "fb2":
      show("FB2 details", renderFb2(result.parsed));
      return;
    case "gif":
      show("GIF details", imagePreviewHtml + renderGif(result.parsed));
      return;
    case "zip":
      show("ZIP details", renderZip(result.parsed));
      return;
    case "sevenZip":
      show("7z details", renderSevenZip(result.parsed));
      return;
    case "tar":
      show("TAR details", renderTar(result.parsed));
      return;
    case "iso9660":
      show("ISO-9660 details", renderIso9660(result.parsed));
      return;
    case "gzip":
      show("gzip details", renderGzip(result.parsed));
      return;
    case "rar":
      show("RAR details", renderRar(result.parsed));
      return;
    case "lnk":
      show("Windows shortcut details", renderLnk(result.parsed));
      return;
    case "png":
      show("PNG details", imagePreviewHtml + renderPng(result.parsed));
      return;
    case "bmp":
      show("BMP details", imagePreviewHtml + renderBmp(result.parsed));
      return;
    case "tga":
      show("TGA details", renderTga(result.parsed));
      return;
    case "webp":
      show("WebP details", imagePreviewHtml + renderWebp(result.parsed));
      return;
    case "ani":
      show("ANI details", imagePreviewHtml + renderAni(result.parsed));
      return;
    case "webm":
      show("WebM details", videoPreviewHtml + renderWebm(result.parsed), preview);
      return;
    case "mkv":
      show("Matroska (MKV) details", videoPreviewHtml + renderMkv(result.parsed), preview);
      return;
    case "mp4":
      show("MP4 details", videoPreviewHtml + renderMp4(result.parsed), preview);
      return;
    case "mpegps":
      show("MPEG Program Stream details", videoPreviewHtml + renderMpegPs(result.parsed), preview);
      return;
    case "avi":
      show("AVI details", videoPreviewHtml + renderAvi(result.parsed), preview);
      return;
    case "asf":
      show("ASF details", mediaPreviewHtml + renderAsf(result.parsed), preview);
      return;
    case "pcap":
      show("PCAP details", renderPcap(result.parsed));
      return;
    case "pdf":
      show("PDF details", renderPdf(result.parsed));
      return;
    case "mp3":
      show("MP3 details", audioPreviewHtml + renderMp3(result.parsed));
      return;
    case "flac":
      show("FLAC details", audioPreviewHtml + renderFlac(result.parsed));
      return;
    case "wav":
      show("WAV details", audioPreviewHtml + renderWav(result.parsed));
      return;
    default:
      break;
  }

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
