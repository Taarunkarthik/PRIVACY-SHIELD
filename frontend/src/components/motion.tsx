import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

const STORAGE_KEY = 'ps-background-motion';
const REDUCED_QUERY = '(prefers-reduced-motion: reduce)';

/** False where nothing can animate: a DOM without matchMedia or requestAnimationFrame, such as the unit-test DOM. */
export function motionSupported(): boolean {
  return typeof window !== 'undefined'
    && typeof window.matchMedia === 'function'
    && typeof window.requestAnimationFrame === 'function';
}

export function prefersReducedMotion(): boolean {
  return motionSupported() && window.matchMedia(REDUCED_QUERY).matches;
}

/** Whether a one-off animation (the count-up, the mask reveal) may play. */
export function canAnimate(): boolean {
  return motionSupported() && !prefersReducedMotion();
}

function readPaused(): boolean {
  try { return window.localStorage.getItem(STORAGE_KEY) === 'paused'; }
  catch { return false; }
}

// Only a deliberate pause is stored; resuming removes the entry again, so a
// visitor who never touches the control leaves nothing in browser storage.
function storePaused(paused: boolean) {
  try {
    if (paused) window.localStorage.setItem(STORAGE_KEY, 'paused');
    else window.localStorage.removeItem(STORAGE_KEY);
  } catch { /* storage unavailable: the choice lasts for this page only */ }
}

interface Motion {
  /** The browser can animate at all. */
  supported: boolean;
  /** The operating system asks for reduced motion. */
  reduced: boolean;
  /** The person paused the background. */
  paused: boolean;
  togglePaused: () => void;
}

const MotionContext = createContext<Motion>({ supported: false, reduced: false, paused: false, togglePaused: () => {} });

export function MotionProvider({ children }: { children: ReactNode }) {
  const supported = motionSupported();
  const [reduced, setReduced] = useState(prefersReducedMotion);
  const [paused, setPaused] = useState(readPaused);

  useEffect(() => {
    if (!supported) return;
    const query = window.matchMedia(REDUCED_QUERY);
    const update = () => setReduced(query.matches);
    query.addEventListener?.('change', update);
    return () => query.removeEventListener?.('change', update);
  }, [supported]);

  const value = useMemo<Motion>(() => ({
    supported,
    reduced,
    paused,
    togglePaused: () => { storePaused(!paused); setPaused(!paused); },
  }), [supported, reduced, paused]);

  return <MotionContext.Provider value={value}>{children}</MotionContext.Provider>;
}

export function useMotion(): Motion {
  return useContext(MotionContext);
}
