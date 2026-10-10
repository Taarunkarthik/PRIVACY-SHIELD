import { BrowserRouter, Link, Route, Routes } from 'react-router';
import { AuthProvider, useAuth } from './api/auth';
import { Brand } from './components/Brand';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { Connections } from './pages/Connections';
import { SchemaExplorer } from './pages/SchemaExplorer';
import { Scans } from './pages/Scans';
import { Classifications } from './pages/Classifications';
import { Login } from './pages/Login';
import { Policies } from './pages/Policies';
import { Approvals } from './pages/Approvals';
import { Deployments } from './pages/Deployments';
import { AuditLogs } from './pages/AuditLogs';
import { Settings } from './pages/Settings';

function SessionApp() {
  const { user, loading } = useAuth();
  if (loading) return <main className="session-loading" role="status"><Brand /><div className="loading-ring" /><p>Opening your workspace…</p></main>;
  if (!user) return <Login />;
  return <Routes><Route element={<Layout />}><Route index element={<Dashboard />} /><Route path="/connections" element={<Connections />} /><Route path="/schema" element={<SchemaExplorer />} /><Route path="/scans" element={<Scans />} /><Route path="/classifications" element={<Classifications />} /><Route path="/policies" element={<Policies />} /><Route path="/approvals" element={<Approvals />} /><Route path="/deployments" element={<Deployments />} /><Route path="/audit" element={<AuditLogs />} /><Route path="/settings" element={<Settings />} /><Route path="*" element={<div className="page-content"><section className="panel empty-feature"><h1>Page not found</h1><p>This page is not part of your workspace.</p><Link to="/" className="button primary">Back to overview</Link></section></div>} /></Route></Routes>;
}

export function App() {
  return <BrowserRouter><AuthProvider><SessionApp /></AuthProvider></BrowserRouter>;
}
