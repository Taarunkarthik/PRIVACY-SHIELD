import { useEffect, useRef, useState } from 'react';
import { canAnimate } from './reducedMotion';

const DURATION_MS = 700;

/**
 * Counts from zero to `value` once, the first time it is shown. Later changes
 * (a refresh) appear at once, as does everything under reduced motion.
 */
export function CountUp({ value }: { value: number }) {
  const finished = useRef(!canAnimate());
  const [shown, setShown] = useState(() => (finished.current ? value : 0));

  useEffect(() => {
    if (finished.current) { setShown(value); return; }
    const started = performance.now();
    let frame = 0;
    const step = (now: number) => {
      const progress = Math.min(1, Math.max(0, now - started) / DURATION_MS);
      setShown(Math.round(value * (1 - (1 - progress) ** 3)));
      if (progress < 1) frame = window.requestAnimationFrame(step);
      else finished.current = true;
    };
    frame = window.requestAnimationFrame(step);
    return () => window.cancelAnimationFrame(frame);
  }, [value]);

  return <>{shown.toLocaleString()}</>;
}
