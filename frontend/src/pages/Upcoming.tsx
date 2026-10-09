import { ArrowLeft, ArrowUpRight, LockKeyhole } from 'lucide-react';
import { Link } from 'react-router';
import { upcomingPages } from '../routes/navigation';
import { useAuth } from '../api/auth';

export function Upcoming({ page }: { page: typeof upcomingPages[number] }) {
  const { user } = useAuth();
  const Icon = page.icon;
  return <div className="page-content">
    <div className="page-heading"><div><p className="eyebrow">{page.eyebrow}</p><h1>{page.title}</h1></div><span className="pill"><span className="neutral-dot" /> Coming in a later phase</span></div>
    <section className="empty-feature panel">
      <span className="feature-icon"><Icon size={34} strokeWidth={1.4} /></span>
      <h2>{page.heading}</h2><p>{page.description}</p>
      <div className="upcoming-note"><LockKeyhole size={16} /><span>{page.next}</span></div>
      <Link className="button secondary" to="/"><ArrowLeft size={16} /> Back to overview</Link>
    </section>
    {page.path === '/settings' && <section className="panel account-summary"><div><p className="eyebrow">SIGNED-IN ACCOUNT</p><h2>{user?.email}</h2></div><span className="pill">{user?.role}</span></section>}
    <div className="footnote"><ArrowUpRight size={15} /><p>Connections, discovery, scans, and AI recommendations are available. This page is planned for a later phase.</p></div>
  </div>;
}
