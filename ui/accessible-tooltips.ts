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
    popup.style.removeProperty("top");
  }
};

const positionTooltip = (
  control: HTMLElement,
  button: HTMLButtonElement,
  popup: HTMLElement,
  document: Document
): void => {
  control.classList.remove("accessibleTooltip--above");
  popup.style.right = "auto";
  const buttonBounds = button.getBoundingClientRect();
  popup.style.left = `${buttonBounds.left}px`;
  popup.style.top = `${buttonBounds.bottom}px`;
  const bounds = popup.getBoundingClientRect();
  const viewport = document.documentElement;
  if (bounds.bottom > viewport.clientHeight && buttonBounds.top >= bounds.height) {
    control.classList.add("accessibleTooltip--above");
    popup.style.top = `${buttonBounds.top - bounds.height}px`;
  } else if (bounds.bottom > viewport.clientHeight) {
    popup.style.top = `${Math.max(0, viewport.clientHeight - bounds.height)}px`;
  }
  popup.style.left = `${Math.min(
    Math.max(buttonBounds.left, 0),
    Math.max(0, viewport.clientWidth - bounds.width)
  )}px`;
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

const createTooltipPopup = (document: Document, text: string): HTMLElement => {
  const popup = document.createElement("span");
  popup.className = "accessibleTooltipPopup";
  popup.setAttribute("role", "tooltip");
  popup.setAttribute("aria-label", text);
  popup.hidden = true;
  return popup;
};

const attachTooltip = (
  control: HTMLElement,
  button: HTMLButtonElement,
  popup: HTMLElement,
  document: Document
): void => {
  button.addEventListener("click", event => {
    event.stopPropagation();
    const opening = popup.hidden !== false;
    closeOtherTooltips(document, opening ? control : null);
    control.classList.toggle("accessibleTooltip--open", opening);
    button.setAttribute("aria-expanded", String(opening));
    popup.hidden = !opening;
    if (opening) positionTooltip(control, button, popup, document);
  });
};

const configureTooltipButton = (button: HTMLButtonElement, text: string): void => {
  button.title = text;
  button.setAttribute("aria-label", `Show explanation: ${text}`);
  button.setAttribute("aria-expanded", "false");
};

const addAccessibleTooltip = (target: HTMLElement, tooltip: string): void => {
  const text = tooltip.trim();
  if (!text || target.querySelector(":scope > .accessibleTooltip")) return;
  const document = target.ownerDocument;
  ensureTooltipDismissal(document);
  target.setAttribute("title", text);
  const control = document.createElement("span");
  const button = document.createElement("button");
  button.type = "button";
  button.className = "accessibleTooltipButton";
  configureTooltipButton(button, text);
  const popup = createTooltipPopup(document, text);
  control.className = "accessibleTooltip";
  attachTooltip(control, button, popup, document);
  control.append(button, popup);
  target.append(control);
};

const addAccessibleTooltipToButton = (button: HTMLButtonElement, tooltip: string): void => {
  const text = tooltip.trim();
  if (!text || button.parentElement?.classList.contains("accessibleTooltip")) return;
  const document = button.ownerDocument;
  ensureTooltipDismissal(document);
  const control = document.createElement("span");
  control.className = "accessibleTooltip nativeHashTooltip";
  const popup = createTooltipPopup(document, text);
  configureTooltipButton(button, text);
  attachTooltip(control, button, popup, document);
  button.replaceWith(control);
  control.append(button, popup);
};

const updateAccessibleTooltipButton = (button: HTMLButtonElement, tooltip: string): void => {
  const text = tooltip.trim();
  if (!text) return;
  configureTooltipButton(button, text);
  button.parentElement?.querySelector<HTMLElement>(".accessibleTooltipPopup")
    ?.setAttribute("aria-label", text);
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

export {
  accessibleTooltipSelector,
  addAccessibleTooltip,
  addAccessibleTooltipToButton,
  enhanceAccessibleTooltips,
  updateAccessibleTooltipButton
};
