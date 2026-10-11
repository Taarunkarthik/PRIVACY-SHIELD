import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CountUp } from '../src/components/CountUp';
import { DataField } from '../src/components/DataField';
import { maskValue, syntheticValue } from '../src/components/fieldEngine';
import { MaskReveal } from '../src/components/MaskReveal';
import { MotionProvider, useMotion } from '../src/components/motion';

/** Gives the test DOM what a browser has, so the animated paths run. Frames are queued and never fire. */
function allowMotion({ reduced = false } = {}) {
  const matchMedia = (query: string) => ({ matches: reduced, media: query, addEventListener() {}, removeEventListener() {} });
  window.matchMedia = matchMedia as unknown as typeof window.matchMedia;
  vi.spyOn(window, 'requestAnimationFrame').mockImplementation(() => 1);
  vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => {});
}

// The test DOM has no matchMedia of its own; take ours away again so other tests see it as it is.
afterEach(() => { Reflect.deleteProperty(window, 'matchMedia'); });

describe('background data field', () => {
  it('masks invented values the way the product does, keeping their length', () => {
    expect(maskValue('priya.sharma@example.com')).toBe('p****.******@example.com');
    expect(maskValue('+91 98765 43210')).toBe('+** ***** *3210');
    expect(maskValue('ABCPK1234F')).toBe('******234F');
    expect(maskValue('2345 6789 0124')).toBe('**** **** 0124');
    expect(maskValue('4111 1111 1111 1111')).toBe('**** **** **** 1111');
  });

  it('generates only synthetic values, each with a same-length mask', () => {
    let seed = 7;
    const random = () => { seed = (seed * 16807) % 2147483647; return seed / 2147483647; };
    for (let index = 0; index < 200; index++) {
      const value = syntheticValue(random);
      expect(maskValue(value)).toHaveLength(value.length);
      if (value.includes('@')) expect(value).toMatch(/@(example\.(com|org|net)|(mail|corp)\.example)$/);
    }
  });

  it('renders a decorative canvas without touching it where nothing can be drawn', () => {
    const errors = vi.spyOn(console, 'error');
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext');
    const { container } = render(<MotionProvider><DataField strength="hero" /></MotionProvider>);
    const canvas = container.querySelector('canvas');
    expect(canvas).toHaveAttribute('aria-hidden', 'true');
    expect(getContext).not.toHaveBeenCalled();
    expect(errors).not.toHaveBeenCalled();
  });
});

describe('one-off animations', () => {
  it('shows a total at once where it cannot animate', () => {
    render(<p data-testid="total"><CountUp value={1284} /></p>);
    expect(screen.getByTestId('total')).toHaveTextContent((1284).toLocaleString());
  });

  it('starts a total from zero where it can animate', () => {
    allowMotion();
    render(<p data-testid="total"><CountUp value={1284} /></p>);
    expect(screen.getByTestId('total')).toHaveTextContent('0');
  });

  it('shows a total at once under reduced motion', () => {
    allowMotion({ reduced: true });
    render(<p data-testid="total"><CountUp value={9} /></p>);
    expect(screen.getByTestId('total')).toHaveTextContent('9');
  });

  it('gives assistive technology the masked value from the first frame while a hidden copy scrambles', () => {
    allowMotion();
    const { container } = render(<MaskReveal from="priya.sharma@example.com" to="p***@example.com" />);
    expect(container.querySelector('code .sr-only')).toHaveTextContent('p***@example.com');
    expect(container.querySelector('code [aria-hidden="true"]')).toHaveTextContent('priya.sharma@example.com');
  });

  it('shows only the masked value under reduced motion', () => {
    allowMotion({ reduced: true });
    const { container } = render(<MaskReveal from="priya.sharma@example.com" to="p***@example.com" />);
    expect(container.querySelector('code')).toHaveTextContent(/^p\*\*\*@example\.com$/);
    expect(container.querySelector('[aria-hidden="true"]')).toBeNull();
  });
});

describe('background motion preference', () => {
  function Toggle() {
    const motion = useMotion();
    return <button onClick={motion.togglePaused}>{motion.paused ? 'paused' : 'moving'}</button>;
  }

  it('stores only a deliberate pause and clears it again on resume', async () => {
    allowMotion();
    const visitor = userEvent.setup({ delay: null });
    render(<MotionProvider><Toggle /></MotionProvider>);
    expect(localStorage.length).toBe(0);
    await visitor.click(screen.getByRole('button', { name: 'moving' }));
    expect(localStorage.getItem('ps-background-motion')).toBe('paused');
    await visitor.click(screen.getByRole('button', { name: 'paused' }));
    expect(localStorage.length).toBe(0);
  });

  it('keeps working when browser storage is unavailable', async () => {
    allowMotion();
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked'); });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('blocked'); });
    const visitor = userEvent.setup({ delay: null });
    render(<MotionProvider><Toggle /></MotionProvider>);
    await visitor.click(screen.getByRole('button', { name: 'moving' }));
    expect(screen.getByRole('button', { name: 'paused' })).toBeInTheDocument();
  });
});
