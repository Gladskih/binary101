const activeAnimations = new WeakMap<HTMLElement, number>();

const startAnimation = (button: HTMLButtonElement, root: HTMLElement): void => {
  const status = root.querySelector<HTMLOutputElement>("[data-pe-animation-status]");
  const frames = Array.from(root.querySelectorAll<HTMLElement>("[data-pe-animation-frame]"));
  const steps = (root.dataset["peAnimationSteps"] ?? "").split(",").map(value => {
    const [frame, duration] = value.split(":").map(Number);
    return { frame: frame!, duration: duration! };
  });
  if (!steps.length || steps.some(step => !Number.isInteger(step.frame) || step.frame < 0 ||
    step.frame >= frames.length || !Number.isFinite(step.duration) || step.duration <= 0)) {
    if (status) status.textContent = "Playback unavailable: invalid frame sequence or timing.";
    return;
  }
  let index = 0;
  let deadline = performance.now();
  const tick = (now: number): void => {
    if (!root.isConnected) { activeAnimations.delete(root); return; }
    if (now >= deadline) {
      const step = steps[index]!;
      frames.forEach((frame, frameIndex) => { frame.hidden = frameIndex !== step.frame; });
      if (status) status.textContent = `Step ${index + 1} / ${steps.length}; frame ${step.frame + 1}`;
      deadline = now + step.duration;
      index = (index + 1) % steps.length;
    }
    activeAnimations.set(root, requestAnimationFrame(tick));
  };
  button.textContent = "Pause";
  activeAnimations.set(root, requestAnimationFrame(tick));
};

export const handleResourceAnimationClick = (event: Event): void => {
  const button = typeof Element !== "undefined" && event.target instanceof Element
    ? event.target.closest<HTMLButtonElement>("[data-pe-animation-play]") : null;
  const root = button?.closest<HTMLElement>("[data-pe-animation]");
  if (!button || !root) return;
  const status = root.querySelector<HTMLOutputElement>("[data-pe-animation-status]");
  const running = activeAnimations.get(root);
  if (running !== undefined) {
    cancelAnimationFrame(running); activeAnimations.delete(root);
    button.textContent = "Play";
    if (status) status.textContent = "Stopped";
    return;
  }
  startAnimation(button, root);
};
