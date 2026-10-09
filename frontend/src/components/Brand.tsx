export function Brand({ compact = false }: { compact?: boolean }) {
  return <span className="brand">
    <svg viewBox="0 0 40 44" fill="none" aria-hidden="true" className="brand-mark">
      <path d="M20 3 36 9v12c0 9-7.3 15.6-16 20C11.3 36.6 4 30 4 21V9L20 3Z" fill="currentColor" opacity=".14" />
      <path d="M20 3 36 9v12c0 9-7.3 15.6-16 20C11.3 36.6 4 30 4 21V9L20 3Z" stroke="currentColor" strokeWidth="2.4" />
      <path d="m13 21 5 5 10-11" stroke="currentColor" strokeWidth="2.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
    {!compact && <span className="brand-wordmark">Privacy<span>Shield</span><small>DATA PRIVACY WORKSPACE</small></span>}
  </span>;
}
