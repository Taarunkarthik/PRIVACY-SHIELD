export function Brand({ compact = false }: { compact?: boolean }) {
  return <span className="brand">
    {/* An ensō — a single ink ring, deliberately left open. Drawn in currentColor. */}
    <svg viewBox="0 0 360 360" fill="none" aria-hidden="true" className="brand-mark">
      <path d="M250 72 C300 108 316 170 296 222 C276 274 220 306 166 300 C112 294 66 252 62 198 C58 144 92 96 142 78 C168 68 196 68 220 78" stroke="currentColor" strokeWidth="24" strokeLinecap="round" />
    </svg>
    {!compact && <span className="brand-wordmark">Privacy<span>Shield</span><small>Data privacy workspace</small></span>}
  </span>;
}
