import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router';
import { ChevronRight, LogOut, Menu, Pause, Play, ShieldCheck, X } from 'lucide-react';
import { useAuth } from '../api/auth';
import { Brand } from './Brand';
import { useMotion } from './motion';
import { navigation } from '../routes/navigation';

// Navigation groups, in display order. The keys match `group` in routes/navigation.
const groups = [['WORKSPACE', 'Workspace'], ['DISCOVER', 'Discover'], ['PROTECT', 'Protect'], ['MANAGE', 'Manage']] as const;

// Routes reachable from in-page links but not shown in the primary navigation.
const secondaryTitles: Record<string, string> = { '/deployments': 'Deployments' };

export function Layout() {
  const { user, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const [error, setError] = useState('');
  const location = useLocation();
  const motion = useMotion();
  const title = navigation.find((item) => item.path === location.pathname)?.label
    ?? secondaryTitles[location.pathname]
    ?? 'Page not found';

  useEffect(() => {
    document.title = `${title} · PrivacyShield`;
  }, [title]);

  useEffect(() => {
    if (!menuOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMenuOpen(false);
        document.querySelector<HTMLButtonElement>('.mobile-menu')?.focus();
      }
    };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [menuOpen]);

  async function handleLogout() {
    setSigningOut(true);
    setError('');
    try { await logout(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Sign out failed. Please try again.'); }
    finally { setSigningOut(false); }
  }

  return <div className="app-shell">
    <a href="#main-content" className="skip-link">Skip to content</a>
    {menuOpen && <button className="mobile-backdrop" aria-label="Close navigation" onClick={() => setMenuOpen(false)} />}
    <aside className={`sidebar ${menuOpen ? 'open' : ''}`} id="workspace-navigation">
      <div className="sidebar-brand"><Brand /><button className="icon-button mobile-close" aria-label="Close navigation" onClick={() => setMenuOpen(false)}><X size={20} /></button></div>
      <div className="workspace-switch"><span className="workspace-avatar">P</span><span><strong>Privacy workspace</strong><small>Local environment</small></span><span className="status-dot" /></div>
      <nav aria-label="Main navigation">
        {groups.map(([group, groupLabel]) => <div className="nav-group" key={group}><p>{groupLabel}</p>{navigation.filter((item) => item.group === group && (!item.adminOnly || user?.role === 'ADMIN')).map(({ path, label, icon: Icon }) => <NavLink key={path} to={path} end={path === '/'} onClick={() => { setMenuOpen(false); setError(''); }} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Icon size={18} strokeWidth={1.7} /><span>{label}</span></NavLink>)}</div>)}
      </nav>
      <div className="sidebar-bottom"><ShieldCheck size={19} /><div><strong>Your data stays yours</strong><p>A private, local workspace</p></div></div>
      <div className="sidebar-user"><span className="user-avatar">{user?.email.slice(0, 1).toUpperCase()}</span><div><strong title={user?.email}>{user?.email}</strong><small>{user?.role === 'ADMIN' ? 'Administrator' : user?.role === 'ANALYST' ? 'Analyst' : 'Auditor'}</small></div><button className="icon-button" aria-label="Sign out" title="Sign out" onClick={handleLogout} disabled={signingOut}><LogOut size={17} /></button></div>
    </aside>
    <div className="main-wrap">
      <header className="topbar"><div className="breadcrumbs"><button className="icon-button mobile-menu" aria-label="Open navigation" aria-expanded={menuOpen} aria-controls="workspace-navigation" onClick={() => setMenuOpen(true)}><Menu size={22} /></button><span>Workspace</span><ChevronRight size={14} /><strong>{title}</strong></div><div className="topbar-right">
        {/* Shown only where the background actually moves: not under reduced motion, where it is a still frame. */}
        {motion.supported && !motion.reduced && <button type="button" className="motion-toggle" onClick={motion.togglePaused} aria-label={motion.paused ? 'Resume background motion' : 'Pause background motion'} title={motion.paused ? 'Resume background motion' : 'Pause background motion'}>{motion.paused ? <Play size={14} /> : <Pause size={14} />}<span aria-hidden="true">Background</span></button>}
        <span className="environment-tag"><span className="status-dot" /> Local workspace</span>
      </div></header>
      <main id="main-content" tabIndex={-1}>{error && <div className="shell-error error-box" role="alert">{error}</div>}<Outlet /></main>
    </div>
  </div>;
}
