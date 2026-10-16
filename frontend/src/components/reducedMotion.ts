/**
 * Whether the browser can and should animate: a real DOM that supports
 * `matchMedia`, and no reduced-motion preference. The screen-scrambling and
 * count-up embellishments read this; everything else is plain declarative CSS.
 */
export function canAnimate(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false;
  return !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}
