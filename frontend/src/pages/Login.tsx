import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { ArrowRight, Eye, EyeOff } from 'lucide-react';
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
        <div className="kicker">Postgres privacy control plane</div>
        <div className="sqlcap">create view … with (<b>security_barrier</b> = true)</div>
        <h1>Personal data, found and masked.</h1>
        <p>PrivacyShield scans your PostgreSQL tables for emails, phone numbers, PAN and Aadhaar numbers, then deploys masked views once a person has approved the rules.</p>
      </div>
      <p className="login-footer">
        <span>Every record behind this page is invented. Nothing leaves this local workspace.</span>
      </p>
    </section>
    <section className="login-form-panel">
      <div className="login-form-wrap">
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
    </section>
  </main>;
}
