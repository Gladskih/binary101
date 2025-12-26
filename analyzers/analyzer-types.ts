"use strict";

import type { PeParseResult } from "./pe/index.js";
import type { JpegParseResult } from "./jpeg/types.js";
import type { ElfParseResult } from "./elf/types.js";
import type { Fb2ParseResult } from "./fb2/index.js";
import type { GifParseResult } from "./gif/types.js";
import type { ZipParseResult } from "./zip/index.js";
import type { PngParseResult } from "./png/types.js";
import type { PdfParseResult } from "./pdf/types.js";
import type { WebpParseResult } from "./webp/types.js";
import type { WebmParseResult } from "./webm/types.js";
import type { Mp3ParseResult } from "./mp3/types.js";
import type { FlacParseResult } from "./flac/types.js";
import type { SevenZipParseResult } from "./sevenz/index.js";
import type { TarParseResult } from "./tar/types.js";
import type { GzipParseResult } from "./gzip/types.js";
import type { RarParseResult } from "./rar/index.js";
import type { MzParseResult } from "./mz/index.js";
import type { LnkParseResult } from "./lnk/types.js";
import type { Mp4ParseResult } from "./mp4/types.js";
import type { WavParseResult } from "./wav/types.js";
import type { AviParseResult } from "./avi/types.js";
import type { AniParseResult } from "./ani/types.js";
import type { SqliteParseResult } from "./sqlite/types.js";
import type { AsfParseResult } from "./asf/types.js";
import type { MpegPsParseResult } from "./mpegps/types.js";
import type { PcapParseResult } from "./pcap/types.js";

export type AnalyzerName =
  | "lnk"
  | "sqlite"
  | "elf"
  | "pe"
  | "mz"
  | "fb2"
  | "gif"
  | "sevenZip"
  | "rar"
  | "tar"
  | "gzip"
  | "zip"
  | "pdf"
  | "png"
  | "jpeg"
  | "webp"
  | "webm"
  | "mp3"
  | "flac"
  | "mp4"
  | "mpegps"
  | "pcap"
  | "wav"
  | "avi"
  | "ani"
  | "asf";

type AnalyzerParseMap = {
  lnk: LnkParseResult;
  sqlite: SqliteParseResult;
  elf: ElfParseResult;
  pe: PeParseResult;
  mz: MzParseResult;
  fb2: Fb2ParseResult;
  gif: GifParseResult;
  sevenZip: SevenZipParseResult;
  rar: RarParseResult;
  tar: TarParseResult;
  gzip: GzipParseResult;
  zip: ZipParseResult;
  pdf: PdfParseResult;
  png: PngParseResult;
  jpeg: JpegParseResult;
  webp: WebpParseResult;
  webm: WebmParseResult;
  mp3: Mp3ParseResult;
  flac: FlacParseResult;
  mp4: Mp4ParseResult;
  mpegps: MpegPsParseResult;
  pcap: PcapParseResult;
  wav: WavParseResult;
  avi: AviParseResult;
  ani: AniParseResult;
  asf: AsfParseResult;
};

type AnalyzerResultUnion = {
  [Name in AnalyzerName]: { analyzer: Name; parsed: AnalyzerParseMap[Name] };
}[AnalyzerName];

export type ParseForUiResult = AnalyzerResultUnion | { analyzer: null; parsed: null };

export type ParsedByAnalyzer<Name extends AnalyzerName> =
  Extract<ParseForUiResult, { analyzer: Name }>["parsed"];
