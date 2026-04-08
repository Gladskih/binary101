"use strict";

import { DOMParser as XmlDomParser } from "@xmldom/xmldom";
import type { ManifestXmlDocumentParser } from "../../analyzers/pe/resources/preview/manifest-xml.js";

export const parseManifestTestXmlDocument: ManifestXmlDocumentParser = text =>
  new XmlDomParser({ onError: () => {} }).parseFromString(text, "application/xml");
