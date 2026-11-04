import type { ResourceAnimation } from "../../analyzers/pe/resources/preview/ani-animation.js";

export const renderResourceAnimation = (animation: ResourceAnimation): string => {
  const sequence = (animation.flags & 2) ? animation.sequence : animation.frames.map((_frame, index) => index);
  const steps = sequence.map((frame, index) => ({ frame,
    // ANI rates are in 1/60 second jiffies (Microsoft Multimedia Standards Update).
    duration: (animation.rates[index] ?? animation.defaultJiffies) * 1000 / 60 }));
  return `<div data-pe-animation data-pe-animation-steps="${steps.map(step =>
    `${step.frame}:${step.duration}`).join(",")}"><button type="button" data-pe-animation-play>Play</button> ` +
    `<output data-pe-animation-status>Stopped</output><div class="peAnimation__frames">` +
    animation.frames.map((frame, index) => `<span data-pe-animation-frame="${index}" ` +
      `${index ? "hidden" : ""}>${frame.url ? `<img src="${frame.url}" ` +
        `alt="Animation frame ${index + 1}" />` : "Frame unavailable"}</span>`).join("") +
    `</div><details><summary>All ${animation.frames.length} frames</summary>` +
    animation.frames.map((frame, index) => frame.url ? `<figure><img src="${frame.url}" ` +
      `alt="Frame ${index + 1}" /><figcaption>${index + 1}${frame.hotspot
        ? `; hotspot ${frame.hotspot.x}, ${frame.hotspot.y}` : ""}</figcaption></figure>` :
      `<p>Frame ${index + 1} is unavailable.</p>`).join("") + `</details></div>`;
};
