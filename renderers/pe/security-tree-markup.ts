"use strict";

import type { AuthenticodeCheckStatus } from "../../analyzers/pe/authenticode/index.js";
import { safe } from "../../html-utils.js";

export type TreeBadgeStatus = AuthenticodeCheckStatus | "info";

export interface TreeBadge {
  label: string;
  status: TreeBadgeStatus;
  detail?: string;
  modifier?: string;
}

const BADGE_ICONS: Record<TreeBadgeStatus, string> = {
  pass: "&#10003;",
  fail: "&#10007;",
  unknown: "&#9888;",
  info: ""
};

export const formatCheckDetail = (title: string, detail: string | undefined): string =>
  detail ? `${title}: ${detail}` : title;

export const createRoleBadge = (
  label: string,
  modifier?: string,
  detail?: string
): TreeBadge => ({
  label,
  status: "info",
  ...(detail ? { detail } : {}),
  ...(modifier ? { modifier } : {})
});

export const createInfoBadge = (label: string, detail?: string): TreeBadge => ({
  label,
  status: "info",
  ...(detail ? { detail } : {})
});

export const createStatusBadge = (
  label: string,
  status: AuthenticodeCheckStatus,
  detail: string
): TreeBadge => ({
  label,
  status,
  detail
});

export const filterBadges = (badges: Array<TreeBadge | undefined>): TreeBadge[] =>
  badges.filter((badge): badge is TreeBadge => badge != null);

const getNodeStatus = (badges: TreeBadge[]): TreeBadgeStatus => {
  const statuses = badges.map(badge => badge.status);
  if (statuses.includes("fail")) return "fail";
  if (statuses.includes("unknown")) return "unknown";
  if (statuses.includes("pass")) return "pass";
  return "info";
};

const renderTreeBadge = (badge: TreeBadge): string =>
  `<span class="peSecurityTreeBadge peSecurityTreeBadge--${badge.status}${
    badge.modifier ? ` peSecurityTreeBadge--${badge.modifier}` : ""
  }"${badge.detail ? ` title="${safe(badge.detail)}"` : ""}>${
    BADGE_ICONS[badge.status]
      ? `<span class="peSecurityTreeBadgeIcon" aria-hidden="true">${BADGE_ICONS[badge.status]}</span>`
      : ""
  }<span>${safe(badge.label)}</span></span>`;

export const renderTreeMeta = (label: string, value: string | undefined): string =>
  value
    ? `<div class="smallNote peSecurityTreeMeta"><span>${safe(label)}:</span> ${safe(value)}</div>`
    : "";

export const renderTreeNode = (
  title: string,
  badges: TreeBadge[],
  meta: string[],
  children?: string,
  titleDetail?: string
): string => (
  `<li class="peSecurityTreeItem">` +
  `<div class="peSecurityTreeNode peSecurityTreeNode--${getNodeStatus(badges)}">` +
  `<div class="peSecurityTreeTitleRow">` +
  `<div class="peSecurityTreeTitle"${titleDetail ? ` title="${safe(titleDetail)}"` : ""}>${safe(title)}</div>` +
  `<div class="peSecurityTreeBadges">${badges.map(renderTreeBadge).join("")}</div>` +
  `</div>${meta.join("")}</div>` +
  (children ? `<ul class="peSecurityTree">${children}</ul>` : "") +
  `</li>`
);
