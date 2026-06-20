"use strict";

const enhancedDocuments = new WeakSet<Document>();
const accessibleTooltipSelector = "[data-accessible-tooltip][title]";

const closeTooltip = (control: HTMLElement): void => {
  control.classList.remove("accessibleTooltip--open");
  control.classList.remove("accessibleTooltip--above");
  const button = control.querySelector<HTMLButtonElement>(".accessibleTooltipButton");
  const popup = control.querySelector<HTMLElement>(".accessibleTooltipPopup");
  if (button) button.setAttribute("aria-expanded", "false");
  if (popup) {
    popup.hidden = true;
    popup.style.removeProperty("left");
    popup.style.removeProperty("right");
  }
};

const positionTooltip = (
  control: HTMLElement,
  button: HTMLButtonElement,
  popup: HTMLElement,
  document: Document
): void => {
  popup.style.left = "0";
  popup.style.right = "auto";
  const initialBounds = popup.getBoundingClientRect();
  const viewport = document.documentElement;
  if (initialBounds.bottom > viewport.clientHeight && button.getBoundingClientRect().top >= initialBounds.height) {
    control.classList.add("accessibleTooltip--above");
  }
  const bounds = popup.getBoundingClientRect();
  const left = Math.min(Math.max(bounds.left, 0), viewport.clientWidth - bounds.width);
  popup.style.left = `${left - bounds.left}px`;
};

const closeOtherTooltips = (document: Document, keep: HTMLElement | null): void => {
  document.querySelectorAll<HTMLElement>(".accessibleTooltip--open").forEach(control => {
    if (control !== keep) closeTooltip(control);
  });
};

const ensureTooltipDismissal = (document: Document): void => {
  if (enhancedDocuments.has(document)) return;
  enhancedDocuments.add(document);
  document.addEventListener("click", event => {
    const target = event.target;
    if (target instanceof Node && target.parentElement?.closest(".accessibleTooltip")) return;
    closeOtherTooltips(document, null);
  });
  document.addEventListener("keydown", event => {
    if (event.key === "Escape") closeOtherTooltips(document, null);
  });
};

const addAccessibleTooltip = (target: HTMLElement, tooltip: string): void => {
  const text = tooltip.trim();
  if (!text || target.querySelector(":scope > .accessibleTooltip")) return;
  const document = target.ownerDocument;
  ensureTooltipDismissal(document);
  target.setAttribute("title", text);
  const control = document.createElement("span");
  const button = document.createElement("button");
  const popup = document.createElement("span");
  control.className = "accessibleTooltip";
  button.type = "button";
  button.className = "accessibleTooltipButton";
  button.title = text;
  button.setAttribute("aria-label", `Show explanation: ${text}`);
  button.setAttribute("aria-expanded", "false");
  popup.className = "accessibleTooltipPopup";
  popup.setAttribute("role", "tooltip");
  popup.setAttribute("aria-label", text);
  popup.hidden = true;
  button.addEventListener("click", event => {
    event.stopPropagation();
    const opening = popup.hidden !== false;
    closeOtherTooltips(document, opening ? control : null);
    control.classList.toggle("accessibleTooltip--open", opening);
    button.setAttribute("aria-expanded", String(opening));
    popup.hidden = !opening;
    if (opening) positionTooltip(control, button, popup, document);
  });
  control.append(button, popup);
  target.append(control);
};

const enhanceAccessibleTooltips = (root: HTMLElement): void => {
  root.querySelectorAll<HTMLElement>(accessibleTooltipSelector).forEach(target => {
    const tooltip = target.getAttribute("title")?.trim() ?? "";
    if (
      !tooltip ||
      target.matches("button, a, img, [aria-label]") ||
      target.closest(".accessibleTooltip")
    ) {
      return;
    }
    addAccessibleTooltip(target, tooltip);
  });
};

export { accessibleTooltipSelector, addAccessibleTooltip, enhanceAccessibleTooltips };
