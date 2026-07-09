"use strict";

type TypeRule = { pattern: RegExp; canonical: string };
type TypeComparison = "match" | "analyzer-more-specific" | "mismatch";

const ANALYZER_RULES: TypeRule[] = [
  { pattern: /^Unknown binary type$/, canonical: "unknown" },
  { pattern: /^Empty file$/, canonical: "empty" },
  { pattern: /^ELF\b/, canonical: "elf" },
  { pattern: /^Mach-O\b/, canonical: "macho" },
  { pattern: /^COFF object file\b/, canonical: "coff" },
  { pattern: /^PE(?:32|\b)|^MS-DOS MZ|^NE executable|^Linear executable/, canonical: "pe" },
  { pattern: /^Windows Metadata \(WinMD\) \(PE/, canonical: "pe" },
  { pattern: /^\.NET reference assembly \(metadata-only\) \(PE/, canonical: "pe" },
  { pattern: /^CLR native image \(PE/, canonical: "pe" },
  { pattern: /^MUI resource-only image \(PE/, canonical: "pe" },
  { pattern: /^ZIP|^Microsoft Word document|^Microsoft Excel workbook/, canonical: "zip" },
  { pattern: /^Microsoft PowerPoint presentation|^OpenXML Office/, canonical: "zip" },
  { pattern: /^OpenDocument|^EPUB|^Android application package/, canonical: "zip" },
  { pattern: /^Visual Studio extension package|^Java archive|^XPS document/, canonical: "zip" },
  { pattern: /^FictionBook e-book inside ZIP/, canonical: "zip" },
  { pattern: /^Chrome extension package /, canonical: "zip" },
  { pattern: /^PDF document/, canonical: "pdf" },
  { pattern: /^Microsoft Compound File|^Microsoft .* binary document/, canonical: "compound" },
  { pattern: /^Windows Installer package|^Microsoft Compiled HTML Help/, canonical: "compound" },
  { pattern: /^PNG image$/, canonical: "png" },
  { pattern: /^JPEG image/, canonical: "jpeg" },
  { pattern: /^GIF image$/, canonical: "gif" },
  { pattern: /^BMP bitmap image$/, canonical: "bmp" },
  { pattern: /^TIFF image$/, canonical: "tiff" },
  { pattern: /^WebP image$/, canonical: "webp" },
  { pattern: /^ICO\/CUR icon image$/, canonical: "icon" },
  { pattern: /^Windows animated cursor/, canonical: "ani" },
  { pattern: /^TGA image/, canonical: "tga" },
  { pattern: /^HEIF\/HEIC image/, canonical: "heif" },
  { pattern: /^AVIF image/, canonical: "avif" },
  { pattern: /^FLAC audio$/, canonical: "flac" },
  { pattern: /^Ogg container/, canonical: "ogg" },
  { pattern: /^WAVE audio/, canonical: "wav" },
  { pattern: /^AIFF\/AIFFC audio$/, canonical: "aiff" },
  { pattern: /^MIDI audio$/, canonical: "midi" },
  { pattern: /^AMR audio$/, canonical: "amr" },
  { pattern: /^Dolby AC-3 audio$/, canonical: "ac3" },
  { pattern: /^DTS audio$/, canonical: "dts" },
  { pattern: /^MPEG audio/, canonical: "mpeg-audio" },
  { pattern: /^FLV video$/, canonical: "flv" },
  { pattern: /^AVI\/DivX video/, canonical: "avi" },
  { pattern: /^ASF container/, canonical: "asf" },
  { pattern: /^MP4\/QuickTime|^ISO-BMFF/, canonical: "mp4" },
  { pattern: /^3GPP\/3GP/, canonical: "3gp" },
  { pattern: /^MPEG Program Stream/, canonical: "mpeg-video" },
  { pattern: /^MPEG Transport Stream/, canonical: "mpeg-transport" },
  { pattern: /^RealMedia container/, canonical: "realmedia" },
  { pattern: /^Matroska\/WebM container$/, canonical: "matroska" },
  { pattern: /^gzip compressed data$/, canonical: "gzip" },
  { pattern: /^bzip2 compressed data$/, canonical: "bzip2" },
  { pattern: /^7z archive$/, canonical: "7z" },
  { pattern: /^XZ compressed data$/, canonical: "xz" },
  { pattern: /^LZ4 frame$/, canonical: "lz4" },
  { pattern: /^Zstandard compressed data/, canonical: "zstd" },
  { pattern: /^RAR archive$/, canonical: "rar" },
  { pattern: /^Microsoft Cabinet archive/, canonical: "cab" },
  { pattern: /^Unix ar archive \((?:static|thin static) library\)$/, canonical: "ar" },
  { pattern: /^TAR archive$/, canonical: "tar" },
  { pattern: /^ISO-9660 CD\/DVD image/, canonical: "iso9660" },
  { pattern: /^Windows Imaging Format archive /, canonical: "wim" },
  {
    pattern: /^SQLite (?:3\.x database|WAL-index shared-memory file)$/,
    canonical: "sqlite"
  },
  { pattern: /^MSDelta patch payload \(PA3[01]\)$/, canonical: "msdelta" },
  { pattern: /^Java class file$/, canonical: "java-class" },
  { pattern: /^DjVu document$/, canonical: "djvu" },
  { pattern: /^PCAP-NG capture file$/, canonical: "pcapng" },
  { pattern: /^PCAP capture file$/, canonical: "pcap" },
  { pattern: /^Windows shortcut/, canonical: "lnk" },
  { pattern: /^WebAssembly binary/, canonical: "wasm" },
  { pattern: /^Android DEX bytecode$/, canonical: "dex" },
  { pattern: /^Windows Help file/, canonical: "hlp" },
  { pattern: /^Compiled terminfo entry /, canonical: "terminfo" },
  { pattern: /^Windows setup information file /, canonical: "setupscript" },
  { pattern: /^GNU gettext message catalog /, canonical: "gettext" },
  { pattern: /^Windows Application Compatibility Database /, canonical: "sdb" },
  { pattern: /^OpenType font collection /, canonical: "font-ttf" },
  { pattern: /^TrueType\/OpenType font /, canonical: "font-ttf" },
  { pattern: /^Web Open Font Format 2 font /, canonical: "font-woff2" },
  { pattern: /^Web Open Font Format font /, canonical: "font-woff" },
  { pattern: /^Python bytecode cache /, canonical: "python-bytecode" },
  { pattern: /^PEM armor block /, canonical: "pem" },
  { pattern: /^PostScript document /, canonical: "postscript" },
  { pattern: /^PostScript Printer Description file /, canonical: "ppd" },
  { pattern: /^Text script|^Text file$/, canonical: "text" },
  { pattern: /^HTML document$/, canonical: "html" },
  { pattern: /^SVG image/, canonical: "svg" },
  { pattern: /^XML document$/, canonical: "xml" },
  { pattern: /^JSON data$/, canonical: "json" },
  { pattern: /^RTF document$/, canonical: "rtf" },
  { pattern: /^FictionBook e-book \(FB2\)$/, canonical: "xml" }
];

const FILE_MIME_RULES: TypeRule[] = [
  { pattern: /^application\/octet-stream$/, canonical: "unknown" },
  { pattern: /^inode\/x-empty$/, canonical: "empty" },
  { pattern: /^application\/x-dosexec$/, canonical: "pe" },
  { pattern: /^application\/vnd\.microsoft\.portable-executable$/, canonical: "pe" },
  { pattern: /^application\/x-ms-ne-executable$/, canonical: "pe" },
  { pattern: /^application\/x-(executable|sharedlib|object|pie-executable)$/, canonical: "elf" },
  { pattern: /^application\/x-mach-binary$/, canonical: "macho" },
  { pattern: /^application\/x-coff$/, canonical: "coff" },
  { pattern: /^application\/zip$/, canonical: "zip" },
  { pattern: /^application\/x-zip-compressed$/, canonical: "zip" },
  { pattern: /^application\/vnd\.openxmlformats-officedocument\./, canonical: "zip" },
  { pattern: /^application\/vnd\.oasis\.opendocument\./, canonical: "zip" },
  { pattern: /^application\/epub\+zip$/, canonical: "zip" },
  { pattern: /^application\/vnd\.nuget\.package$/, canonical: "zip" },
  { pattern: /^application\/(java-archive|x-java-archive)$/, canonical: "zip" },
  { pattern: /^application\/x-chrome-extension$/, canonical: "zip" },
  { pattern: /^application\/pdf$/, canonical: "pdf" },
  { pattern: /^application\/(x-ole-storage|CDFV2)$/, canonical: "compound" },
  { pattern: /^application\/msword$/, canonical: "compound" },
  { pattern: /^application\/vnd\.ms-cab-compressed$/, canonical: "cab" },
  { pattern: /^application\/vnd\.ms-opentype$/, canonical: "font-ttf" },
  { pattern: /^application\/vnd\.ms-fontobject$/, canonical: "font-eot" },
  { pattern: /^application\/vnd\.ms-/, canonical: "compound" },
  { pattern: /^application\/x-msi$/, canonical: "compound" },
  { pattern: /^image\/png$/, canonical: "png" },
  { pattern: /^image\/jpeg$/, canonical: "jpeg" },
  { pattern: /^image\/gif$/, canonical: "gif" },
  { pattern: /^image\/(bmp|x-ms-bmp)$/, canonical: "bmp" },
  { pattern: /^image\/tiff$/, canonical: "tiff" },
  { pattern: /^image\/webp$/, canonical: "webp" },
  { pattern: /^image\/(vnd\.microsoft\.icon|x-icon)$/, canonical: "icon" },
  { pattern: /^image\/x-win-bitmap$/, canonical: "icon" },
  { pattern: /^application\/x-navi-animation$/, canonical: "ani" },
  { pattern: /^image\/x-tga$/, canonical: "tga" },
  { pattern: /^image\/(heif|heic)$/, canonical: "heif" },
  { pattern: /^image\/avif$/, canonical: "avif" },
  { pattern: /^audio\/flac$/, canonical: "flac" },
  { pattern: /^audio\/ogg$/, canonical: "ogg" },
  { pattern: /^audio\/(x-wav|wav)$/, canonical: "wav" },
  { pattern: /^audio\/(midi|x-midi)$/, canonical: "midi" },
  { pattern: /^audio\/amr$/, canonical: "amr" },
  { pattern: /^audio\/ac3$/, canonical: "ac3" },
  { pattern: /^audio\/vnd\.dts$/, canonical: "dts" },
  { pattern: /^audio\/mpeg$/, canonical: "mpeg-audio" },
  { pattern: /^video\/x-flv$/, canonical: "flv" },
  { pattern: /^video\/x-msvideo$/, canonical: "avi" },
  { pattern: /^video\/x-ms-asf$/, canonical: "asf" },
  { pattern: /^video\/(mp4|quicktime)$/, canonical: "mp4" },
  { pattern: /^audio\/x-m4a$/, canonical: "mp4" },
  { pattern: /^video\/3gpp$/, canonical: "3gp" },
  { pattern: /^video\/mpeg$/, canonical: "mpeg-video" },
  { pattern: /^video\/mp2t$/, canonical: "mpeg-transport" },
  { pattern: /^application\/vnd\.rn-realmedia$/, canonical: "realmedia" },
  { pattern: /^video\/(webm|x-matroska)$/, canonical: "matroska" },
  { pattern: /^application\/gzip$/, canonical: "gzip" },
  { pattern: /^application\/x-bzip2$/, canonical: "bzip2" },
  { pattern: /^application\/x-7z-compressed$/, canonical: "7z" },
  { pattern: /^application\/x-xz$/, canonical: "xz" },
  { pattern: /^application\/x-lz4$/, canonical: "lz4" },
  { pattern: /^application\/zstd$/, canonical: "zstd" },
  { pattern: /^application\/x-rar$/, canonical: "rar" },
  { pattern: /^application\/x-archive$/, canonical: "ar" },
  { pattern: /^application\/x-tar$/, canonical: "tar" },
  { pattern: /^application\/x-iso9660-image$/, canonical: "iso9660" },
  { pattern: /^application\/x-ms-wim$/, canonical: "wim" },
  { pattern: /^application\/(vnd\.sqlite3|x-sqlite3)$/, canonical: "sqlite" },
  { pattern: /^application\/x-java-applet$/, canonical: "java-class" },
  { pattern: /^image\/vnd\.djvu$/, canonical: "djvu" },
  { pattern: /^application\/(vnd\.tcpdump\.pcap|x-pcapng)$/, canonical: "pcap" },
  { pattern: /^application\/x-ms-shortcut$/, canonical: "lnk" },
  { pattern: /^application\/wasm$/, canonical: "wasm" },
  { pattern: /^application\/x-dex$/, canonical: "dex" },
  { pattern: /^application\/(?:winhlp|x-winhelp)$/, canonical: "hlp" },
  { pattern: /^application\/x-terminfo2?$/, canonical: "terminfo" },
  { pattern: /^application\/x-setupscript$/, canonical: "setupscript" },
  { pattern: /^application\/x-gettext-translation$/, canonical: "gettext" },
  { pattern: /^application\/x-ms-sdb$/, canonical: "sdb" },
  { pattern: /^font\/ttf$/, canonical: "font-ttf" },
  { pattern: /^font\/woff2$/, canonical: "font-woff2" },
  { pattern: /^font\/woff$/, canonical: "font-woff" },
  { pattern: /^application\/x-bytecode\.python$/, canonical: "python-bytecode" },
  { pattern: /^application\/x-pem-file$/, canonical: "pem" },
  { pattern: /^application\/postscript$/, canonical: "postscript" },
  { pattern: /^application\/vnd\.cups-ppd$/, canonical: "ppd" },
  { pattern: /^(application|text)\/javascript$/, canonical: "text" },
  { pattern: /^application\/x-wine-extension-ini$/, canonical: "text" },
  { pattern: /^application\/x-mswinurl$/, canonical: "text" },
  { pattern: /^text\/plain$/, canonical: "text" },
  { pattern: /^text\/x-shellscript$/, canonical: "text" },
  { pattern: /^text\/html$/, canonical: "html" },
  { pattern: /^image\/svg\+xml$/, canonical: "svg" },
  { pattern: /^(text|application)\/xml$/, canonical: "xml" },
  { pattern: /^application\/xhtml\+xml$/, canonical: "xml" },
  { pattern: /^application\/json$/, canonical: "json" },
  { pattern: /^application\/x-ndjson$/, canonical: "json" },
  { pattern: /^(text|application)\/rtf$/, canonical: "rtf" },
  { pattern: /^text\//, canonical: "text" }
];

const applyRules = (value: string, rules: TypeRule[]): string => {
  for (const rule of rules) {
    if (rule.pattern.test(value)) return rule.canonical;
  }
  return "unmapped";
};

const normalizeAnalyzerLabel = (label: string): string => applyRules(label, ANALYZER_RULES);

const normalizeFileMimeType = (mimeType: string): string =>
  applyRules(mimeType.trim(), FILE_MIME_RULES);

const isTextRefinement = (canonical: string): boolean =>
  ["html", "svg", "xml", "json", "rtf", "setupscript", "pem", "postscript", "ppd"].includes(
    canonical
  );

const compareTypes = (analyzerLabel: string, fileMimeType: string): TypeComparison => {
  const analyzerCanonical = normalizeAnalyzerLabel(analyzerLabel);
  const fileCanonical = normalizeFileMimeType(fileMimeType);
  if (analyzerCanonical === fileCanonical) return "match";
  if (
    fileCanonical === "unknown" &&
    analyzerCanonical !== "unknown" &&
    analyzerCanonical !== "unmapped"
  ) return "analyzer-more-specific";
  if (fileCanonical === "text" && isTextRefinement(analyzerCanonical)) {
    return "analyzer-more-specific";
  }
  return "mismatch";
};

const typesMatch = (analyzerLabel: string, fileMimeType: string): boolean =>
  compareTypes(analyzerLabel, fileMimeType) !== "mismatch";

export { compareTypes, normalizeAnalyzerLabel, normalizeFileMimeType, typesMatch };
export type { TypeComparison };
