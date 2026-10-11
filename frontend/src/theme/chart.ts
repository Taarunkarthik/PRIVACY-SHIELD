/**
 * Chart colours for the dark surface. Recharts takes its colours as props,
 * so the values in src/theme/tokens.css are mirrored here.
 *
 * `exposed` and `masked` are the chart-weight steps of the product's two
 * accents (amber = exposed, mint = masked). `risk` is a one-hue ordinal ramp,
 * brightest for the most severe level. All were checked with the dataviz
 * palette validator against the panel colour as rendered, #11373d: the pair as a
 * categorical palette in dark mode, the ramp with --ordinal.
 */
export const chart = {
  exposed: '#bd8526',
  masked: '#2ea686',
  risk: { CRITICAL: '#ffd88f', HIGH: '#e7a93d', MEDIUM: '#b9802a', LOW: '#8d6025' } as Record<string, string>,
  // Text and chrome never take a series colour.
  text: '#eef6f3',
  textMuted: '#bcd3d2',
  axis: 'rgba(168, 214, 212, 0.32)',
  hover: 'rgba(255, 255, 255, 0.06)',
  tooltip: { background: '#0a272d', border: 'rgba(168, 214, 212, 0.32)' },
} as const;
