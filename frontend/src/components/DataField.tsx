import { useEffect, useRef } from 'react';
import { createDataField } from './fieldEngine';
import type { DataFieldController, FieldStrength } from './fieldEngine';
import { useMotion } from './motion';

/**
 * Full-viewport canvas behind the whole application. It is decoration only:
 * hidden from assistive technology, never focusable, and it ignores the pointer
 * so every click reaches the page above it.
 */
export function DataField({ strength }: { strength: FieldStrength }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const controller = useRef<DataFieldController | null>(null);
  const { supported, reduced, paused } = useMotion();
  const animated = supported && !reduced && !paused;
  // The latest values, read when the controller is created.
  const latest = useRef({ strength, animated });
  latest.current = { strength, animated };

  useEffect(() => {
    // Without matchMedia and requestAnimationFrame (the unit-test DOM) there is nothing to draw on.
    if (!supported || !canvas.current) return;
    let context: CanvasRenderingContext2D | null = null;
    try { context = canvas.current.getContext('2d'); } catch { context = null; }
    if (!context) return;
    const field = createDataField(canvas.current, context, latest.current.strength);
    field.setAnimated(latest.current.animated);
    controller.current = field;
    return () => { field.destroy(); controller.current = null; };
  }, [supported]);

  useEffect(() => { controller.current?.setStrength(strength); }, [strength]);
  useEffect(() => { controller.current?.setAnimated(animated); }, [animated]);

  return <canvas ref={canvas} className="data-field" aria-hidden="true" />;
}
