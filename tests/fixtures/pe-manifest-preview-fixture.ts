"use strict";

import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";
import type { PeResources } from "../../analyzers/pe/resources/index.js";
import type { ResourceLangWithPreview, ResourceManifestPreview, ResourceManifestTreeNode, ResourceManifestValidation } from "../../analyzers/pe/resources/preview/types.js";
export type ManifestIncidentalValues = {
  nextLabel: (prefix: string) => string;
  nextLang: () => number;
  nextResourceId: () => number;
};

export type ManifestFixtureSpec = {
  assemblyName?: string | null;
  assemblyVersion?: string | null;
  lang?: number | null;
  manifestVersion?: string | null;
  processorArchitecture?: string | null;
  requestedExecutionLevel?: string | null;
  resourceId?: number | null;
  supportedArchitectures?: string[];
};

type ManifestXmlFixtureSpec = ManifestFixtureSpec & {
  declarationEncoding?: string;
  rootName?: string;
  supportedOsIds?: string[];
};

export const createManifestIncidentalValues = (start = 0): ManifestIncidentalValues => {
  let current = start >>> 0;
  const nextUint32 = (): number => {
    current = (current + 1) >>> 0;
    return current;
  };
  return {
    nextLabel: (prefix: string) => `${prefix}-${nextUint32().toString(16)}`,
    nextLang: () => 0x400 + (nextUint32() & 0xff),
    nextResourceId: () => 0x100 + (nextUint32() & 0xff)
  };
};

const withDefaults = (
  incidental: ManifestIncidentalValues,
  spec: ManifestFixtureSpec = {}
): Required<ManifestFixtureSpec> => ({
  assemblyName: spec.assemblyName === undefined ? incidental.nextLabel("manifest-name") : spec.assemblyName,
  assemblyVersion: spec.assemblyVersion === undefined ? incidental.nextLabel("manifest-version") : spec.assemblyVersion,
  lang: spec.lang === undefined ? incidental.nextLang() : spec.lang,
  manifestVersion: spec.manifestVersion === undefined ? incidental.nextLabel("manifest-root-version") : spec.manifestVersion,
  processorArchitecture:
    spec.processorArchitecture === undefined
      ? incidental.nextLabel("manifest-arch")
      : spec.processorArchitecture,
  requestedExecutionLevel: spec.requestedExecutionLevel === undefined ? null : spec.requestedExecutionLevel,
  resourceId: spec.resourceId === undefined ? incidental.nextResourceId() : spec.resourceId,
  supportedArchitectures: spec.supportedArchitectures === undefined ? [] : spec.supportedArchitectures
});

export const createManifestTextFixture = (incidental = createManifestIncidentalValues()): string =>
  `<${incidental.nextLabel("manifest-root")} />`;

export const createManifestInfoFixture = (
  spec: ManifestFixtureSpec = {},
  incidental = createManifestIncidentalValues()
): ResourceManifestPreview => {
  const values = withDefaults(incidental, spec);
  return {
    manifestVersion: values.manifestVersion,
    assemblyType: incidental.nextLabel("assembly-type"),
    assemblyName: values.assemblyName,
    assemblyVersion: values.assemblyVersion,
    processorArchitecture: values.processorArchitecture,
    requestedExecutionLevel: values.requestedExecutionLevel,
    requestedUiAccess: false,
    supportedArchitectures: values.supportedArchitectures
  };
};

export const createManifestTreeFixture = (
  spec: ManifestFixtureSpec = {},
  incidental = createManifestIncidentalValues()
): ResourceManifestTreeNode => {
  const values = withDefaults(incidental, spec);
  return {
    name: "assembly",
    attributes: values.manifestVersion == null ? [] : [{ name: "manifestVersion", value: values.manifestVersion }],
    text: null,
    children: [
      {
        name: "assemblyIdentity",
        attributes: [
          { name: "type", value: incidental.nextLabel("assembly-type") },
          ...(values.assemblyName == null ? [] : [{ name: "name", value: values.assemblyName }]),
          ...(values.assemblyVersion == null ? [] : [{ name: "version", value: values.assemblyVersion }]),
          ...(values.processorArchitecture == null
            ? []
            : [{ name: "processorArchitecture", value: values.processorArchitecture }])
        ],
        text: null,
        children: []
      },
      {
        name: "trustInfo",
        attributes: [],
        text: null,
        children: [
          {
            name: "security",
            attributes: [],
            text: null,
            children: [
              {
                name: "requestedExecutionLevel",
                attributes: [
                  ...(values.requestedExecutionLevel == null
                    ? []
                    : [{ name: "level", value: values.requestedExecutionLevel }]),
                  { name: "uiAccess", value: "false" }
                ],
                text: null,
                children: []
              }
            ]
          }
        ]
      }
    ]
  };
};

export const createManifestValidationMessageFixture = (
  machine: number,
  spec: Pick<ManifestFixtureSpec, "lang" | "processorArchitecture" | "resourceId"> = {},
  incidental = createManifestIncidentalValues()
): string => {
  const values = withDefaults(incidental, spec);
  return `Manifest ${values.resourceId == null ? "unnamed ID" : `ID ${values.resourceId}`} / ` +
    `${values.lang == null ? "LANG neutral" : `LANG ${values.lang}`} declares ` +
    `processorArchitecture="${values.processorArchitecture}", ` +
    `which is consistent with COFF Machine ${machine.toString(16)}.`;
};

export const createManifestValidationFixture = (machine: number,
  spec: Pick<ManifestFixtureSpec, "lang" | "processorArchitecture" | "resourceId"> = {},
  warnings: string[] = [], incidental = createManifestIncidentalValues()): ResourceManifestValidation => ({
  status: warnings.length ? "warnings" : "consistent",
  checkedCount: warnings.length ? warnings.length + 1 : 2,
  validated: [createManifestValidationMessageFixture(machine, spec, incidental)],
  warnings
});

export const createManifestLangFixture = (
  spec: ManifestFixtureSpec = {},
  incidental = createManifestIncidentalValues()
): ResourceLangWithPreview => {
  const values = withDefaults(incidental, spec);
  return {
    lang: values.lang,
    size: 128,
    codePage: 65001,
    dataRVA: 0,
    reserved: 0,
    previewKind: "text",
    textPreview: createManifestTextFixture(incidental),
    manifestInfo: createManifestInfoFixture(values, incidental)
  };
};

export const createManifestResourcesFixture = (specs: ManifestFixtureSpec[],
  incidental = createManifestIncidentalValues()): {
  entries: Array<Required<Pick<ManifestFixtureSpec, "lang" | "resourceId">>>;
  resources: PeResources;
} => {
  const entries = specs.map(spec => withDefaults(incidental, spec));
  return {
    entries: entries.map(entry => ({
      resourceId: entry.resourceId,
      lang: entry.lang
    })),
    resources: {
      top: [],
      detail: [{
        typeName: "MANIFEST",
        entries: entries.map(entry => ({
          id: entry.resourceId,
          name: null,
          langs: [createManifestLangFixture(entry, incidental)]
        }))
      }]
    }
  };
};

export const createClrHeaderFixture = (flags: number): PeClrHeader => ({
  cb: 0x48,
  MajorRuntimeVersion: 2,
  MinorRuntimeVersion: 5,
  MetaDataRVA: 0,
  MetaDataSize: 0,
  Flags: flags,
  EntryPointToken: 0,
  ResourcesRVA: 0,
  ResourcesSize: 0,
  StrongNameSignatureRVA: 0,
  StrongNameSignatureSize: 0,
  CodeManagerTableRVA: 0,
  CodeManagerTableSize: 0,
  VTableFixupsRVA: 0,
  VTableFixupsSize: 0,
  ExportAddressTableJumpsRVA: 0,
  ExportAddressTableJumpsSize: 0,
  ManagedNativeHeaderRVA: 0,
  ManagedNativeHeaderSize: 0
});

export const createManifestXmlFixture = (spec: ManifestXmlFixtureSpec = {},
  incidental = createManifestIncidentalValues()): {
  manifestInfo: Required<ManifestFixtureSpec>;
  xml: string;
} => {
  const values = withDefaults(incidental, spec);
  const compatibility =
    spec.supportedOsIds == null || spec.supportedOsIds.length === 0
      ? ""
      : "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application>" +
        spec.supportedOsIds.map(id => `<supportedOS Id="${id}" />`).join("") +
        "</application></compatibility>";
  return {
    manifestInfo: values,
    xml:
      `<?xml version="1.0" encoding="${spec.declarationEncoding || "UTF-8"}"?>` +
      `<${spec.rootName || "assembly"} manifestVersion="${values.manifestVersion}" ` +
      "xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">" +
      `<assemblyIdentity type="${incidental.nextLabel("assembly-type")}" ` +
      `name="${values.assemblyName}" version="${values.assemblyVersion}" ` +
      `processorArchitecture="${values.processorArchitecture}" />` +
      compatibility +
      "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><security>" +
      "<requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" +
      (values.requestedExecutionLevel == null
        ? ""
        : `<requestedExecutionLevel level="${values.requestedExecutionLevel}" uiAccess="false" />`) +
      "</requestedPrivileges></security></trustInfo>" +
      "<asmv3:application><asmv3:windowsSettings " +
      "xmlns=\"http://schemas.microsoft.com/SMI/2024/WindowsSettings\">" +
      `<supportedArchitectures>${values.supportedArchitectures.join(" ")}</supportedArchitectures>` +
      "</asmv3:windowsSettings></asmv3:application>" +
      `</${spec.rootName || "assembly"}>`
  };
};

export const createPrefixedManifestXmlFixture = (incidental = createManifestIncidentalValues(),
  spec: ManifestFixtureSpec = {}): {
  manifestInfo: Required<ManifestFixtureSpec>;
  xml: string;
} => {
  const values = withDefaults(incidental, spec);
  return {
    manifestInfo: values,
    xml:
      `<asmv1:assembly xmlns:asmv1="urn:schemas-microsoft-com:asm.v1" ` +
      `xmlns:asmv3="urn:schemas-microsoft-com:asm.v3" manifestVersion="${values.manifestVersion}">` +
      `<asmv1:assemblyIdentity name="${values.assemblyName}" ` +
      `processorArchitecture="${values.processorArchitecture}" />` +
      "<asmv3:application><asmv3:windowsSettings>" +
      "<asmv3:supportedArchitectures>   </asmv3:supportedArchitectures>" +
      "</asmv3:windowsSettings></asmv3:application>" +
      "</asmv1:assembly>"
  };
};

export const createMalformedManifestXmlFixture = (
  spec: Pick<ManifestFixtureSpec, "processorArchitecture" | "requestedExecutionLevel"> = {},
  incidental = createManifestIncidentalValues()
): string => {
  const values = withDefaults(incidental, spec);
  return "<assembly manifestVersion=\"fixture-root\"><assemblyIdentity " +
    `processorArchitecture="${values.processorArchitecture}" />` +
  "<trustInfo><security><requestedPrivileges>" +
  `<requestedExecutionLevel level="${values.requestedExecutionLevel || incidental.nextLabel("execution-level")}" ` +
  "uiAccess=\"maybe\">" +
  "</requestedPrivileges></security></trustInfo>";
};

export const createInvalidUiAccessManifestXmlFixture = (
  spec: Pick<ManifestFixtureSpec, "processorArchitecture" | "requestedExecutionLevel"> = {},
  incidental = createManifestIncidentalValues()
): string => {
  const values = withDefaults(incidental, spec);
  return (
  "<assembly manifestVersion=\"fixture-root\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" +
  `<assemblyIdentity processorArchitecture="${values.processorArchitecture}" />` +
  "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\"><security>" +
  "<requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" +
  `<requestedExecutionLevel level="${values.requestedExecutionLevel || incidental.nextLabel("execution-level")}" ` +
  "uiAccess=\"maybe\" />" +
  "</requestedPrivileges></security></trustInfo>" +
  "</assembly>"
  );
};
