import { useState } from 'react';
import type { FormEvent } from 'react';
import { LockKeyhole, Save, X } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../api/auth';
import type { Connection, ConnectionInput } from '../api/connections';
import { connectionError } from '../api/connections';

export function ConnectionForm({ connection, onSaved, onCancel }: { connection?: Connection; onSaved: () => void; onCancel: () => void }) {
  const { user } = useAuth();
  const [details, setDetails] = useState({
    name: connection?.name ?? '', host: connection?.host ?? 'target-db', port: String(connection?.port ?? 5432),
    database_name: connection?.database_name ?? 'enterprise_demo', ssl_mode: connection?.ssl_mode ?? 'disable',
    scanner_username: connection?.scanner_username ?? 'ps_scanner', deployer_username: connection?.deployer_username ?? '',
    is_active: connection?.is_active ?? true,
  });
  const [scannerPassword, setScannerPassword] = useState('');
  const [deployerPassword, setDeployerPassword] = useState('');
  const [changeDeployer, setChangeDeployer] = useState(false);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const scannerPasswordRequired = !connection || details.scanner_username !== connection.scanner_username;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (user?.role !== 'ADMIN') return;
    setSaving(true);
    setError('');
    const payload: ConnectionInput = {
      name: details.name.trim(), host: details.host.trim(), port: Number(details.port), database_name: details.database_name.trim(),
      ssl_mode: details.ssl_mode, scanner_username: details.scanner_username.trim(),
      ...(connection ? { is_active: details.is_active } : {}),
      ...(scannerPassword ? { scanner_password: scannerPassword } : {}),
      ...(changeDeployer ? { deployer_username: details.deployer_username.trim(), deployer_password: deployerPassword } : {}),
    };
    // Clear password inputs as soon as the request is made, including failure paths.
    setScannerPassword('');
    setDeployerPassword('');
    try {
      await api<Connection>(connection ? `/connections/${encodeURIComponent(connection.id)}` : '/connections', {
        method: connection ? 'PATCH' : 'POST', csrfToken: user.csrf_token, body: JSON.stringify(payload),
      });
      onSaved();
    } catch (reason) { setError(connectionError(reason)); }
    finally { setSaving(false); }
  }

  return <section className="panel connection-form-panel" aria-label={connection ? 'Edit database connection' : 'Add database connection'}>
    <div className="panel-heading"><div><h2>{connection ? 'Edit database connection' : 'Add database connection'}</h2><p>Use credentials authorized to read your selected database schemas.</p></div><button type="button" className="icon-button" aria-label="Close connection form" onClick={onCancel} disabled={saving}><X size={18} /></button></div>
    <form onSubmit={submit} className="connection-form">
      <fieldset disabled={saving}>
        <div className="form-grid">
          <div className="form-field span-two"><label htmlFor="connection-name">Connection name</label><input autoFocus id="connection-name" value={details.name} onChange={(event) => setDetails({ ...details, name: event.target.value })} placeholder="e.g. Synthetic enterprise" required maxLength={120} /></div>
          <div className="form-field"><label htmlFor="connection-host">Database host</label><input id="connection-host" value={details.host} onChange={(event) => setDetails({ ...details, host: event.target.value })} required maxLength={255} spellCheck={false} /></div>
          <div className="form-field"><label htmlFor="connection-port">Port</label><input id="connection-port" type="number" min={1} max={65535} value={details.port} onChange={(event) => setDetails({ ...details, port: event.target.value })} required /></div>
          <div className="form-field"><label htmlFor="connection-database">Database name</label><input id="connection-database" value={details.database_name} onChange={(event) => setDetails({ ...details, database_name: event.target.value })} required maxLength={63} spellCheck={false} /></div>
          <div className="form-field"><label htmlFor="connection-ssl">TLS mode</label><select id="connection-ssl" value={details.ssl_mode} onChange={(event) => setDetails({ ...details, ssl_mode: event.target.value as Connection['ssl_mode'] })}><option value="disable">Disabled — local demo only</option><option value="require">Require encryption</option><option value="verify-ca">Verify certificate authority</option><option value="verify-full">Verify certificate and hostname</option></select></div>
          <div className="form-field"><label htmlFor="scanner-username">Scanner username</label><input id="scanner-username" value={details.scanner_username} onChange={(event) => setDetails({ ...details, scanner_username: event.target.value })} required maxLength={63} autoComplete="off" spellCheck={false} /></div>
          <div className="form-field"><label htmlFor="scanner-password">Scanner password{connection && <span> · {scannerPasswordRequired ? 'required for changed user' : 'leave blank to keep'}</span>}</label><input id="scanner-password" type="password" value={scannerPassword} onChange={(event) => setScannerPassword(event.target.value)} required={scannerPasswordRequired} maxLength={1024} autoComplete="new-password" /></div>
        </div>
        <label className="checkbox-field"><input type="checkbox" checked={changeDeployer} onChange={(event) => { setChangeDeployer(event.target.checked); setDeployerPassword(''); }} /><span>{connection?.deployer_username ? 'Replace deployment credentials' : 'Add deployment credentials'} <small>Optional; not needed for discovery.</small></span></label>
        {changeDeployer && <div className="form-grid deployment-fields"><div className="form-field"><label htmlFor="deployer-username">Deployment username</label><input id="deployer-username" value={details.deployer_username} onChange={(event) => setDetails({ ...details, deployer_username: event.target.value })} required maxLength={63} autoComplete="off" spellCheck={false} /></div><div className="form-field"><label htmlFor="deployer-password">Deployment password</label><input id="deployer-password" type="password" value={deployerPassword} onChange={(event) => setDeployerPassword(event.target.value)} required maxLength={1024} autoComplete="new-password" /></div></div>}
        {connection && <label className="checkbox-field"><input type="checkbox" checked={details.is_active} onChange={(event) => setDetails({ ...details, is_active: event.target.checked })} /><span>Connection is active <small>Inactive connections keep their saved discovery history.</small></span></label>}
      </fieldset>
      {error && <p className="error-box" role="alert">{error} Password fields have been cleared.</p>}
      <div className="form-actions"><p><LockKeyhole size={14} /> Passwords are encrypted and never displayed.</p><div><button type="button" className="button secondary" onClick={onCancel} disabled={saving}>Cancel</button><button type="submit" className="button primary" disabled={saving}><Save size={15} />{saving ? 'Saving…' : 'Save connection'}</button></div></div>
    </form>
  </section>;
}
