/**
 * The living background: rows of invented records drifting sideways while a
 * scan line and the pointer mask them, the way the product masks real columns.
 *
 * Everything here is synthetic. Emails use reserved example domains, and the
 * phone, PAN, Aadhaar and card shapes are generated from a fixed seed.
 */

const ALNUM = /[A-Za-z0-9]/;

/**
 * The product's format-preserving masks, same length out as in: letters and
 * digits become `*`, punctuation and spaces stay, a number keeps its last four
 * characters, and an email keeps its first character and its domain.
 */
export function maskValue(value: string): string {
  const at = value.indexOf('@');
  if (at > 0) {
    const hidden = Array.from(value.slice(1, at), (ch) => (ALNUM.test(ch) ? '*' : ch)).join('');
    return value[0] + hidden + value.slice(at);
  }
  let kept = 0;
  let out = '';
  for (let index = value.length - 1; index >= 0; index--) {
    const ch = value[index];
    if (!ALNUM.test(ch)) { out = ch + out; continue; }
    out = (kept < 4 ? ch : '*') + out;
    kept++;
  }
  return out;
}

/** Small deterministic generator, so a still frame is the same on every visit. */
function seeded(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const FIRST = ['priya', 'arjun', 'kavya', 'rohan', 'ananya', 'vikram', 'meera', 'dev', 'sana', 'nikhil', 'isha', 'rahul', 'tara', 'aditya', 'neha', 'kabir'];
const LAST = ['sharma', 'mehta', 'nair', 'iyer', 'rao', 'singh', 'pillai', 'kapoor', 'khan', 'joshi', 'verma', 'das', 'menon', 'gupta', 'bose', 'reddy'];
const DOMAINS = ['example.com', 'example.org', 'example.net', 'mail.example', 'corp.example'];
const LETTERS = 'ABCDEFGHJKLMNPRSTUVWXYZ';

/** One invented value shaped like the personal data the scanner looks for. */
export function syntheticValue(random: () => number): string {
  const pick = <T,>(items: readonly T[] | string) => items[Math.floor(random() * items.length)];
  const digits = (count: number) => Array.from({ length: count }, () => Math.floor(random() * 10)).join('');
  const roll = random();
  if (roll < 0.3) return `${pick(FIRST)}.${pick(LAST)}@${pick(DOMAINS)}`;
  if (roll < 0.52) return `+91 ${6 + Math.floor(random() * 4)}${digits(4)} ${digits(5)}`;
  if (roll < 0.68) return `${pick(LETTERS)}${pick(LETTERS)}${pick(LETTERS)}P${pick(LETTERS)}${digits(4)}${pick(LETTERS)}`;
  if (roll < 0.86) return `${2 + Math.floor(random() * 8)}${digits(3)} ${digits(4)} ${digits(4)}`;
  return `${4 + Math.floor(random() * 2)}${digits(3)} ${digits(4)} ${digits(4)} ${digits(4)}`;
}

interface Row {
  raw: string;
  masked: string;
  /** Characters in one repeat of the row. */
  period: number;
  /** Pixels per second, leftwards. */
  speed: number;
  /** Starting offset in pixels. */
  phase: number;
  /** Per-row brightness, for a little depth. */
  weight: number;
}

function buildRow(index: number, columns: number): Row {
  const random = seeded(0x9e3779b1 ^ Math.imul(index + 1, 0x85ebca6b));
  const target = Math.max(columns, 120);
  let raw = '';
  let masked = '';
  while (raw.length < target) {
    const value = syntheticValue(random);
    const gap = ' '.repeat(3 + Math.floor(random() * 4));
    raw += value + gap;
    masked += maskValue(value) + gap;
  }
  const period = raw.length;
  // Repeated so any window of `columns` characters can be cut with one slice.
  const repeats = Math.ceil((columns + 2) / period) + 1;
  return {
    raw: raw.repeat(repeats),
    masked: masked.repeat(repeats),
    period,
    speed: 7 + random() * 15,
    phase: random() * period * 9,
    weight: 0.55 + random() * 0.45,
  };
}

/** Stable pseudo-random number in [0, 1) for one character of one row. */
function grain(row: number, character: number): number {
  let h = Math.imul(row + 1, 0x27d4eb2d) ^ Math.imul(character + 1, 0x165667b1);
  h = Math.imul(h ^ (h >>> 15), 0x2c1b3c6d);
  return ((h ^ (h >>> 12)) >>> 0) / 4294967296;
}

export type FieldStrength = 'hero' | 'ambient';

/** How strongly the field is drawn: the sign-in page shows it off, the app keeps it out of the way. */
const LEVEL: Record<FieldStrength, number> = { hero: 1, ambient: 0.15 };

const FONT_PX = 14;
const ROW_HEIGHT = 30;
const FRAME_MS = 1000 / 30;
/** Behind the app the field is faint and slow, so half the frame rate and one canvas pixel per CSS pixel are enough. */
const AMBIENT_FRAME_MS = 1000 / 15;
const SCAN_SECONDS = 10;
const SHIELD_RADIUS = 118;
const SHIELD_SECONDS = 2.6;
const AMBER = '247, 189, 85';
const MINT = '116, 232, 194';

interface TrailPoint { x: number; y: number; at: number }

export interface DataFieldController {
  /** Run the animation, or hold a single frame. */
  setAnimated(animated: boolean): void;
  setStrength(strength: FieldStrength): void;
  destroy(): void;
}

export function createDataField(canvas: HTMLCanvasElement, context: CanvasRenderingContext2D, strength: FieldStrength): DataFieldController {
  let width = 0;
  let height = 0;
  let charWidth = FONT_PX * 0.6;
  let columns = 0;
  let rows: Row[] = [];
  let flags = new Uint8Array(0);

  let animated = false;
  let frame = 0;
  let lastPaint = 0;
  /** Seconds of animation shown so far. It stands still while paused, so resuming never jumps. */
  let clock = 0;
  let current = strength;
  let level = LEVEL[strength];
  let targetLevel = level;
  let destroyed = false;

  let pointer: TrailPoint | null = null;
  let trail: TrailPoint[] = [];

  const font = `${FONT_PX}px "IBM Plex Mono", ui-monospace, "SFMono-Regular", Consolas, monospace`;

  function measure() {
    context.font = font;
    const sample = context.measureText('0'.repeat(40)).width / 40;
    if (sample > 0) charWidth = sample;
    columns = Math.ceil(width / charWidth) + 2;
    const count = Math.ceil(height / ROW_HEIGHT) + 1;
    rows = Array.from({ length: count }, (_, index) => buildRow(index, columns));
    flags = new Uint8Array(columns);
  }

  function resize() {
    // Drawn at the display's pixel density, capped at 2x: beyond that the cost grows and the text looks no sharper.
    // At ambient strength the text is too faint for the extra pixels to show, and they are four times the work.
    const ratio = Math.min(window.devicePixelRatio || 1, current === 'ambient' ? 1 : 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    measure();
    // Resizing clears the canvas, so repaint at once rather than leave a blank frame.
    paint(animated);
  }

  /**
   * Draws one frame. `moving` is false for the still frame shown under reduced
   * motion or while paused before anything has played: the scan line sits
   * mid-screen with everything to its left masked.
   */
  function paint(moving: boolean) {
    context.clearRect(0, 0, width, height);
    if (!columns) return;
    context.font = font;
    context.textBaseline = 'middle';

    const still = !moving && clock === 0;
    const cycle = width * 1.3;
    const band = width * 0.52;
    const scanX = still ? width * 0.5 : ((clock / SCAN_SECONDS) % 1) * cycle;
    const now = clock;
    const shield = trail.concat(pointer ? [{ ...pointer, at: now }] : []);

    // The scan line: a thin bright edge with a soft wake behind it.
    if (scanX < width + 2) {
      const wake = context.createLinearGradient(scanX - 170, 0, scanX, 0);
      wake.addColorStop(0, `rgba(${MINT}, 0)`);
      wake.addColorStop(1, `rgba(${MINT}, ${0.11 * level})`);
      context.fillStyle = wake;
      context.fillRect(scanX - 170, 0, 170, height);
      context.fillStyle = `rgba(214, 250, 236, ${0.5 * level})`;
      context.fillRect(scanX - 1, 0, 1.5, height);
    }

    for (let index = 0; index < rows.length; index++) {
      const row = rows[index];
      const y = index * ROW_HEIGHT + ROW_HEIGHT / 2;
      const travelled = row.phase * charWidth + (still ? 0 : clock * row.speed);
      const first = Math.floor(travelled / charWidth);
      const originX = -(travelled - first * charWidth);
      const start = first % row.period;

      for (let column = 0; column < columns; column++) {
        const x = originX + column * charWidth;
        const character = (start + column) % row.period;
        let masked = 0;
        if (still) masked = x < scanX ? 1 : 0;
        else {
          let behind = scanX - x;
          if (behind < 0) behind += cycle;
          // The wake dissolves character by character instead of ending on a hard edge.
          if (behind < band * 0.72 || (behind < band && behind < band * (0.72 + 0.28 * grain(index, character)))) masked = 1;
        }
        flags[column] = masked;
      }

      for (const point of shield) {
        const age = now - point.at;
        if (age >= SHIELD_SECONDS) continue;
        const radius = SHIELD_RADIUS * (1 - (age / SHIELD_SECONDS) ** 2);
        const dy = y - point.y;
        if (Math.abs(dy) >= radius) continue;
        const reach = Math.sqrt(radius * radius - dy * dy);
        const from = Math.max(0, Math.floor((point.x - reach - originX) / charWidth));
        const to = Math.min(columns - 1, Math.ceil((point.x + reach - originX) / charWidth));
        for (let column = from; column <= to; column++) {
          if (flags[column]) continue;
          const dx = originX + (column + 0.5) * charWidth - point.x;
          const edge = radius * (0.8 + 0.2 * grain(index, (start + column) % row.period));
          if (dx * dx + dy * dy < edge * edge) flags[column] = 1;
        }
      }

      // One fillText per run of equally-masked characters; the face is monospace, so runs stay on the grid.
      const maskedInk = `rgba(${MINT}, ${0.5 * level * row.weight})`;
      const rawInk = `rgba(${AMBER}, ${0.6 * level * row.weight})`;
      let runStart = 0;
      for (let column = 1; column <= columns; column++) {
        if (column < columns && flags[column] === flags[runStart]) continue;
        const masked = flags[runStart] === 1;
        const source = masked ? row.masked : row.raw;
        const text = source.substring(start + runStart, start + column);
        if (text.trim()) {
          context.fillStyle = masked ? maskedInk : rawInk;
          context.fillText(text, originX + runStart * charWidth, y);
        }
        runStart = column;
      }
    }
  }

  function tick(time: number) {
    if (!animated || destroyed) return;
    frame = window.requestAnimationFrame(tick);
    const elapsed = time - lastPaint;
    // The full rate while the field is the subject or the pointer is drawing on it; half that once it has settled into the background.
    const settled = current === 'ambient' && level === targetLevel && !trail.length;
    // A little slack, so a display frame that lands a hair early still counts: 30 paints a second at 60 Hz or 120 Hz.
    if (elapsed < (settled ? AMBIENT_FRAME_MS : FRAME_MS) - 4) return;
    lastPaint = time;
    // A long gap (a background tab, a debugger) must not fast-forward the field.
    clock += Math.min(elapsed, 100) / 1000;
    level += (targetLevel - level) * 0.12;
    if (Math.abs(targetLevel - level) < 0.004) level = targetLevel;
    if (trail.length) trail = trail.filter((point) => clock - point.at < SHIELD_SECONDS);
    paint(true);
  }

  function start() {
    window.cancelAnimationFrame(frame);
    if (!animated || destroyed || document.hidden) return;
    lastPaint = performance.now();
    frame = window.requestAnimationFrame(tick);
  }

  function onVisibility() {
    if (document.hidden) window.cancelAnimationFrame(frame);
    else start();
  }

  function onPointerMove(event: PointerEvent) {
    if (!animated) return;
    // The places the pointer has just left keep their mask for a while, then recover.
    const last = trail[trail.length - 1];
    if (pointer && (!last || Math.hypot(last.x - pointer.x, last.y - pointer.y) > 26)) {
      trail.push({ ...pointer, at: clock });
      if (trail.length > 36) trail.shift();
    }
    pointer = { x: event.clientX, y: event.clientY, at: clock };
  }

  function onPointerLeave() {
    if (pointer) trail.push({ ...pointer, at: clock });
    pointer = null;
  }

  window.addEventListener('resize', resize);
  window.addEventListener('pointermove', onPointerMove, { passive: true });
  document.documentElement.addEventListener('pointerleave', onPointerLeave);
  document.addEventListener('visibilitychange', onVisibility);
  resize();
  // The grid depends on the face's real advance width, known only once the font has loaded.
  document.fonts?.load?.(font).then(() => { if (!destroyed) { measure(); if (!animated) paint(false); } }).catch(() => {});

  return {
    setAnimated(next) {
      if (next === animated) return;
      animated = next;
      if (animated) start();
      else { window.cancelAnimationFrame(frame); pointer = null; trail = []; paint(false); }
    },
    setStrength(next) {
      if (next === current) return;
      current = next;
      targetLevel = LEVEL[next];
      if (!animated) level = targetLevel;
      // The pixel density depends on the strength; resizing also repaints.
      resize();
    },
    destroy() {
      destroyed = true;
      window.cancelAnimationFrame(frame);
      window.removeEventListener('resize', resize);
      window.removeEventListener('pointermove', onPointerMove);
      document.documentElement.removeEventListener('pointerleave', onPointerLeave);
      document.removeEventListener('visibilitychange', onVisibility);
    },
  };
}
