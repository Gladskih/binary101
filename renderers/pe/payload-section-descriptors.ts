"use strict";

import type { PePayloadAnalysis } from "../../analyzers/pe/payloads.js";
import {
  getPePayloadSectionDescriptor,
  getResourcePayloadSectionDescriptor
} from "./payloads.js";

export const getPePayloadLazySectionDescriptors = (
  payloads: PePayloadAnalysis | null | undefined
) => {
  const appended = getPePayloadSectionDescriptor(payloads);
  const resources = getResourcePayloadSectionDescriptor(payloads);
  return [
    ...(appended ? [{ ...appended, key: "appended-payloads" as const }] : []),
    ...(resources ? [{ ...resources, key: "resource-payloads" as const }] : [])
  ];
};
