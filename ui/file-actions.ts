"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { createCertificateDownloadClickHandler } from "./certificate-download.js";
import { createGzipClickHandler } from "./gzip-actions.js";
import { createIso9660EntryClickHandler } from "./iso9660-actions.js";
import { createPeChecksumClickHandler } from "./pe-checksum-controls.js";
import { createSectionEntropyClickHandler } from "./section-entropy-controls.js";
import { createPeDosNestedDownloadClickHandler } from "./pe-dos-nested-download.js";
import { createPeLinuxPayloadDownloadClickHandler } from "./pe-linux-payload-download.js";
import { createPeOverlayDownloadClickHandler } from "./pe-overlay-download.js";
import { createPePayloadDownloadClickHandler } from "./pe-payload-download.js";
import { createPeInnoSetupDownloadClickHandler } from "./pe-inno-setup-download.js";
import { createSevenZipEntryClickHandler } from "./sevenz-actions.js";
import { createZipEntryClickHandler } from "./zip-actions.js";

type FileActionDeps = {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
};

type AsyncEventHandler = (event: Event) => Promise<void>;

const runAsyncHandler = (handler: AsyncEventHandler, event: Event): void => {
  void handler(event);
};

export const createFileActionClickHandler = (deps: FileActionDeps) => {
  const peChecksumClickHandler = createPeChecksumClickHandler(deps);
  const sectionEntropyClickHandler = createSectionEntropyClickHandler(deps);
  const isoClickHandler = createIso9660EntryClickHandler(deps);
  const sevenZipClickHandler = createSevenZipEntryClickHandler(deps);
  const gzipClickHandler = createGzipClickHandler(deps);
  const zipClickHandler = createZipEntryClickHandler(deps);
  const peDosNestedDownloadClickHandler = createPeDosNestedDownloadClickHandler(deps);
  const peLinuxPayloadDownloadClickHandler = createPeLinuxPayloadDownloadClickHandler(deps);
  const peOverlayDownloadClickHandler = createPeOverlayDownloadClickHandler(deps);
  const pePayloadDownloadClickHandler = createPePayloadDownloadClickHandler(deps);
  const peInnoSetupDownloadClickHandler = createPeInnoSetupDownloadClickHandler(deps);
  const certificateDownloadClickHandler = createCertificateDownloadClickHandler({
    setStatusMessage: deps.setStatusMessage
  });
  return (event: Event): void => {
    runAsyncHandler(peChecksumClickHandler, event);
    runAsyncHandler(sectionEntropyClickHandler, event);
    runAsyncHandler(isoClickHandler, event);
    runAsyncHandler(sevenZipClickHandler, event);
    runAsyncHandler(gzipClickHandler, event);
    runAsyncHandler(zipClickHandler, event);
    peDosNestedDownloadClickHandler(event);
    peLinuxPayloadDownloadClickHandler(event);
    peOverlayDownloadClickHandler(event);
    pePayloadDownloadClickHandler(event);
    runAsyncHandler(peInnoSetupDownloadClickHandler, event);
    certificateDownloadClickHandler(event);
  };
};
