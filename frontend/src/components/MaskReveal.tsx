import { useEffect, useState } from 'react';
import { canAnimate } from './motion';

const DURATION_MS = 600;
const NOISE = '*#%&$@';

/**
 * Shows a masked value, arriving at it by scrambling the example value it was
 * computed from. Assistive technology and tests read the masked value from the
 * first frame; only an `aria-hidden` copy animates. Under reduced motion, and
 * where nothing can animate, the masked value is simply shown.
 */
export function MaskReveal({ from, to }: { from: string | null; to: string }) {
  const [frame, setFrame] = useState<string | null>(() => (from !== null && from !== to && canAnimate() ? from : null));

  useEffect(() => {
    if (from === null || from === to || !canAnimate()) { setFrame(null); return; }
    const started = performance.now();
    let request = 0;
    const step = (now: number) => {
      const progress = Math.min(1, Math.max(0, now - started) / DURATION_MS);
      if (progress >= 1) { setFrame(null); return; }
      // The text settles left to right and moves steadily towards its final length.
      const length = Math.round(from.length + (to.length - from.length) * progress);
      const settled = Math.floor(to.length * progress);
      let text = '';
      for (let index = 0; index < length; index++) {
        if (index < settled) text += to[index];
        else if (index < settled + 3) text += NOISE[Math.floor(Math.random() * NOISE.length)];
        else text += from[index] ?? '*';
      }
      setFrame(text);
      request = window.requestAnimationFrame(step);
    };
    request = window.requestAnimationFrame(step);
    return () => window.cancelAnimationFrame(request);
  }, [from, to]);

  if (frame === null) return <code className="masked-value">{to}</code>;
  return <code className="masked-value mask-reveal"><span className="sr-only">{to}</span><span aria-hidden="true">{frame}</span></code>;
}
