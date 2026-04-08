"use strict";

import type {
  ResourceManifestPreview,
  ResourceManifestValidation,
  ResourceManifestTreeAttribute,
  ResourceManifestTreeNode
} from "../../analyzers/pe/resources/preview/types.js";
import { dd, safe } from "../../html-utils.js";

const SUPPORTED_OS_LABELS = new Map<string, string>([
  ["{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}", "Windows 10 / 11; Windows Server 2016 / 2019 / 2022"],
  ["{1f676c76-80e1-4239-95bb-83d0f6d0da78}", "Windows 8.1; Windows Server 2012 R2"],
  ["{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}", "Windows 8; Windows Server 2012"],
  ["{35138b9a-5d96-4fbd-8e2d-a2440225f93a}", "Windows 7; Windows Server 2008 R2"],
  ["{e2011457-1546-43c5-a5fe-008deee3d3f0}", "Windows Vista; Windows Server 2008"]
]);

const getSupportedOsLabel = (
  node: ResourceManifestTreeNode,
  attribute: ResourceManifestTreeAttribute
): string | null => {
  if (node.name.split(":").pop()?.toLowerCase() !== "supportedos") return null;
  if (attribute.name.toLowerCase() !== "id") return null;
  return SUPPORTED_OS_LABELS.get(attribute.value.toLowerCase()) || null;
};

const renderAttributeList = (node: ResourceManifestTreeNode): string => {
  if (!node.attributes.length) return "";
  const items = node.attributes
    .map(attribute => {
      const supportedOsLabel = getSupportedOsLabel(node, attribute);
      return `<li><span class="mono">@${safe(attribute.name)}</span>: ${safe(attribute.value)}${supportedOsLabel ? ` <span class="smallNote">(${safe(supportedOsLabel)})</span>` : ""}</li>`;
    })
    .join("");
  return `<ul class="smallNote" style="padding-left:1.1rem;margin:.25rem 0 0 0">${items}</ul>`;
};

const renderNodeText = (text: string | null): string =>
  text
    ? `<div class="mono smallNote" style="margin-top:.25rem;white-space:pre-wrap;word-break:break-word">${safe(text)}</div>`
    : "";

const renderNodeSummary = (node: ResourceManifestTreeNode): string => {
  const parts = [`<span class="mono">&lt;${safe(node.name)}&gt;</span>`];
  if (node.attributes.length) {
    parts.push(
      `<span class="smallNote">${node.attributes.length} attr${node.attributes.length === 1 ? "" : "s"}</span>`
    );
  }
  if (node.children.length) {
    parts.push(
      `<span class="smallNote">${node.children.length} child${node.children.length === 1 ? "" : "ren"}</span>`
    );
  } else if (node.text) {
    const preview = node.text.length > 48 ? `${node.text.slice(0, 45)}...` : node.text;
    parts.push(`<span class="smallNote">${safe(preview)}</span>`);
  }
  return parts.join(" ");
};

const renderManifestTreeNode = (node: ResourceManifestTreeNode, depth: number): string => {
  const body = [
    renderAttributeList(node),
    renderNodeText(node.text),
    node.children.length
      ? `<div style="margin-top:.3rem;padding-left:.8rem;border-left:1px solid var(--border2)">${node.children
          .map(child => renderManifestTreeNode(child, depth + 1))
          .join("")}</div>`
      : ""
  ].join("");
  return (
    `<details style="margin-top:${depth ? ".25rem" : ".2rem"}"${depth === 0 ? " open" : ""}>` +
    `<summary style="cursor:pointer">${renderNodeSummary(node)}</summary>` +
    body +
    "</details>"
  );
};

const createNode = (
  name: string,
  attributes: Record<string, string | null | undefined>,
  children: ResourceManifestTreeNode[] = [],
  text: string | null = null
): ResourceManifestTreeNode => ({
  name,
  attributes: Object.entries(attributes)
    .filter(([, value]) => value != null && value !== "")
    .map(([attributeName, value]) => ({
      name: attributeName,
      value: String(value)
    })),
  text,
  children
});

const countManifestTreeNodes = (node: ResourceManifestTreeNode): number =>
  1 + node.children.reduce((count, child) => count + countManifestTreeNodes(child), 0);

const createSyntheticManifestTree = (
  manifestInfo: ResourceManifestPreview | undefined
): ResourceManifestTreeNode | null => {
  if (!manifestInfo) return null;
  const children: ResourceManifestTreeNode[] = [];
  const assemblyIdentity = createNode("assemblyIdentity", {
    type: manifestInfo.assemblyType,
    name: manifestInfo.assemblyName,
    version: manifestInfo.assemblyVersion,
    processorArchitecture: manifestInfo.processorArchitecture
  });
  if (assemblyIdentity.attributes.length) children.push(assemblyIdentity);
  const requestedExecutionLevel = createNode("requestedExecutionLevel", {
    level: manifestInfo.requestedExecutionLevel,
    uiAccess:
      manifestInfo.requestedUiAccess == null
        ? null
        : manifestInfo.requestedUiAccess
          ? "true"
          : "false"
  });
  if (requestedExecutionLevel.attributes.length) {
    children.push(
      createNode("trustInfo", {}, [
        createNode("security", {}, [
          createNode("requestedPrivileges", {}, [requestedExecutionLevel])
        ])
      ])
    );
  }
  if (manifestInfo.supportedArchitectures.length) {
    children.push(
      createNode("application", {}, [
        createNode("windowsSettings", {}, [
          createNode(
            "supportedArchitectures",
            {},
            [],
            manifestInfo.supportedArchitectures.join(" ")
          )
        ])
      ])
    );
  }
  const root = createNode(
    "assembly",
    { manifestVersion: manifestInfo.manifestVersion },
    children
  );
  return root.attributes.length || root.children.length ? root : null;
};

const renderManifestTreeButton = (
  action: "expand" | "collapse",
  label: string,
  disabled: boolean
): string =>
  `<button type="button" data-manifest-tree-action="${action}"${disabled ? " disabled" : ""} style="cursor:${disabled ? "not-allowed" : "pointer"};opacity:${disabled ? ".55" : "1"};padding:.15rem .45rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg);color:var(--text)">${label}</button>`;

const renderManifestCopyButton = (): string =>
  `<button type="button" data-manifest-copy-button aria-label="Copy manifest XML" title="Copy manifest XML" style="display:inline-flex;align-items:center;justify-content:center;width:1.9rem;height:1.9rem;padding:0;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg);color:var(--text);cursor:pointer">` +
  `<svg aria-hidden="true" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round">` +
  `<rect x="5" y="3" width="8" height="10" rx="1.5"></rect>` +
  `<path d="M3 11.5V5.5C3 4.67 3.67 4 4.5 4H5"></path>` +
  `</svg>` +
  `</button>`;

const renderManifestTreeControls = (tree: ResourceManifestTreeNode): string => {
  const nodeCount = countManifestTreeNodes(tree);
  const expandDisabled = nodeCount <= 1;
  const collapseDisabled = false;
  return (
  `<div class="smallNote" style="display:flex;gap:.35rem;align-items:center;flex-wrap:wrap;margin-top:.2rem">` +
  `<span><b>Parsed tree</b></span>` +
  renderManifestTreeButton("expand", "Expand all", expandDisabled) +
  renderManifestTreeButton("collapse", "Collapse all", collapseDisabled) +
  `</div>`
  );
};

const renderManifestValidationRows = (
  label: string,
  values: string[],
  colorVariable: string,
  tooltip: string
): string =>
  values.length
    ? dd(
        label,
        `<div class="smallNote" style="margin:0;color:${colorVariable}">${values
          .map(value => `<div>- ${safe(value)}</div>`)
          .join("")}</div>`,
        tooltip
      )
    : "";

const renderManifestValidation = (
  manifestValidation: ResourceManifestValidation | undefined
): string => {
  if (!manifestValidation) return "";
  const consistent = manifestValidation.status === "consistent";
  const statusLabel = consistent ? "Consistent" : "Warnings";
  const statusColor = consistent ? "var(--ok-fg)" : "var(--warn-fg)";
  return (
    `<section style="margin-top:.35rem;padding:.45rem .55rem;border:1px solid var(--border2);border-radius:8px;background:var(--bg)">` +
    `<div class="smallNote" style="margin-bottom:.25rem"><b>Manifest cross-check</b></div>` +
    `<div class="smallNote" style="margin-bottom:.35rem">This check compares manifest metadata against PE headers and, when present, the CLR header. It also verifies that multiple embedded manifests agree on shared policy fields.</div>` +
    `<dl>` +
    dd(
      "Status",
      `<span class="smallNote" style="color:${statusColor};font-weight:600">${statusLabel}</span>`,
      consistent
        ? "All implemented manifest cross-checks matched the PE/CLR metadata."
        : "One or more implemented manifest cross-checks contradicted the PE/CLR metadata."
    ) +
    dd("Checks run", String(manifestValidation.checkedCount), "Total manifest cross-check verdicts that produced either a validated match or a warning.") +
    dd("Validated", String(manifestValidation.validated.length), "Cross-checks that matched the PE/CLR metadata or another embedded manifest resource.") +
    dd("Warnings", String(manifestValidation.warnings.length), "Cross-checks that contradict PE/CLR metadata or another embedded manifest resource.") +
    renderManifestValidationRows(
      "Validated details",
      manifestValidation.validated,
      "var(--ok-fg)",
      "Manifest cross-checks that matched the PE/CLR metadata or another embedded manifest."
    ) +
    renderManifestValidationRows(
      "Warning details",
      manifestValidation.warnings,
      "var(--warn-fg)",
      "Manifest cross-checks that contradicted the PE/CLR metadata or another embedded manifest."
    ) +
    `</dl></section>`
  );
};

export const renderManifestTree = (
  manifestInfo: ResourceManifestPreview | undefined,
  manifestTree: ResourceManifestTreeNode | undefined
): string => {
  const tree = manifestTree || createSyntheticManifestTree(manifestInfo);
  if (!tree) return "";
  return (
    `<section data-manifest-tree-viewer style="margin-top:.35rem;padding:.45rem .55rem;border:1px solid var(--border2);border-radius:8px;background:var(--card)">` +
    renderManifestTreeControls(tree) +
    `<div data-manifest-tree style="margin-top:.2rem">${renderManifestTreeNode(tree, 0)}</div>` +
    `</section>`
  );
};

export const renderManifestPreview = (
  textPreview: string,
  manifestInfo: ResourceManifestPreview | undefined,
  manifestTree: ResourceManifestTreeNode | undefined,
  manifestValidation: ResourceManifestValidation | undefined
): string =>
  [
    renderManifestValidation(manifestValidation),
    renderManifestTree(manifestInfo, manifestTree),
    `<section data-manifest-preview style="margin-top:.35rem;padding:.45rem .55rem;border:1px solid var(--border2);border-radius:8px;background:var(--bg)">`,
    `<div style="display:flex;justify-content:flex-end;margin-bottom:.25rem">${renderManifestCopyButton()}</div>`,
    `<div data-manifest-copy-source class="mono smallNote" style="white-space:pre-wrap;word-break:break-word">${safe(textPreview)}</div>`,
    "</section>"
  ].join("");
