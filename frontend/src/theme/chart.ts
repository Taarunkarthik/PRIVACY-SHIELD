/**
 * Chart colours for the light paper surface. Recharts takes its colours as
 * props, so the values in src/theme/tokens.css are mirrored here.
 *
 * `exposed` and `masked` are the chart-weight steps of the product's two
 * accents (amber = exposed, green = masked). `risk` is a categorical ramp
 * across the four meanings — red, amber, indigo, green — so each severity
 * stays apart on paper. All were checked against the panel colour as
 * rendered, #f7f4ec, for normal-vision contrast and CVD separation.
 */
export const chart = {
  exposed: '#b07d2a',
  masked: '#3f7a5e',
  risk: { CRITICAL: '#b23a2e', HIGH: '#956517', MEDIUM: '#33456e', LOW: '#35705a' } as Record<string, string>,
  // Text and chrome never take a series colour.
  text: '#1d1b18',
  textMuted: '#857c6e',
  axis: 'rgba(29, 27, 24, 0.25)',
  hover: 'rgba(29, 27, 24, 0.06)',
  tooltip: { background: '#f7f4ec', border: 'rgba(29, 27, 24, 0.18)' },
} as const;
