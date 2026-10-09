import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { ArrowRight, Eye, EyeOff, LockKeyhole, ShieldCheck } from 'lucide-react';
import { useAuth } from '../api/auth';
import { Brand } from '../components/Brand';

export function Login() {
  const { login, expired, error: connectionError, refresh } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [visible, setVisible] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => { document.title = 'Sign in · PrivacyShield'; }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      await login(email.trim().toLowerCase(), password);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to sign in.');
    } finally {
      setPassword('');
      setVisible(false);
      setSubmitting(false);
    }
  }

  return <main className="login-layout">
    <section className="login-story" aria-label="About PrivacyShield">
      <Brand />
      <div className="login-story-copy">
        <span className="eyebrow light"><span className="status-dot" /> YOUR DATA. YOUR CONTROL.</span>
        <h1>Know what’s sensitive.<br /><em>Protect what matters.</em></h1>
        <p>A clear path from discovering personal data to reviewing and deploying the right protections.</p>
        <div className="privacy-orbit" aria-hidden="true"><div className="orbit-line one" /><div className="orbit-line two" /><div className="orbit-shield"><ShieldCheck size={58} strokeWidth={1.25} /></div><span className="orbit-tag tag-one">Discover</span><span className="orbit-tag tag-two">Review</span><span className="orbit-tag tag-three">Protect</span></div>
      </div>
      <div className="login-footer"><LockKeyhole size={14} /> Private by design. Accountable by default.</div>
    </section>
    <section className="login-form-panel">
      <div className="login-form-wrap">
        <div className="small-icon"><LockKeyhole size={23} /></div>
        <p className="eyebrow">WELCOME TO YOUR WORKSPACE</p>
        <h2>Sign in to PrivacyShield</h2>
        <p className="muted">Continue with your workspace account.</p>
        {expired && <p className="notice" role="status">Your session has expired. Please sign in again.</p>}
        {connectionError && <div className="error-box" role="alert">{connectionError}<button className="text-button" onClick={refresh}>Try connection again</button></div>}
        <form onSubmit={submit} className="login-form">
          <label htmlFor="email">Email address</label>
          <input id="email" name="email" type="email" autoComplete="username" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@organization.com" required maxLength={254} disabled={submitting} />
          <label htmlFor="password">Password</label>
          <div className="password-field">
            <input id="password" name="password" type={visible ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required maxLength={128} disabled={submitting} />
            <button type="button" className="password-toggle" onClick={() => setVisible(!visible)} aria-label={visible ? 'Hide password' : 'Show password'} aria-pressed={visible} disabled={submitting}>{visible ? <EyeOff size={18} /> : <Eye size={18} />}</button>
          </div>
          {error && <p className="error-box" role="alert">{error}</p>}
          <button className="button primary login-submit" disabled={submitting} type="submit">{submitting ? 'Signing in…' : 'Sign in'}{!submitting && <ArrowRight size={17} />}</button>
        </form>
        <p className="login-help">Need access? Contact your workspace administrator.</p>
      </div>
      <span className="login-version">PRIVACYSHIELD · LOCAL WORKSPACE</span>
    </section>
  </main>;
}
