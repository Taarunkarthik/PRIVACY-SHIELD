import { Bot, CircleCheck, Database, FileClock, LayoutDashboard, ScanLine, Settings2, ShieldCheck, Users, Waypoints } from 'lucide-react';

import type { LucideIcon } from 'lucide-react';
import type { Role } from '../api/permissions';

// `roles` narrows an item to some roles; omitting it offers the item to everyone.
export interface NavigationItem { path: string; label: string; icon: LucideIcon; group: string; roles?: Role[] }

export const navigation: NavigationItem[] = [
  { path: '/', label: 'Overview', icon: LayoutDashboard, group: 'WORKSPACE' },
  { path: '/connections', label: 'Connections', icon: Database, group: 'DISCOVER' },
  { path: '/schema', label: 'Schema Explorer', icon: Waypoints, group: 'DISCOVER' },
  { path: '/scans', label: 'Scan Results', icon: ScanLine, group: 'DISCOVER' },
  { path: '/classifications', label: 'AI Classification', icon: Bot, group: 'PROTECT' },
  { path: '/policies', label: 'Masking Policies', icon: ShieldCheck, group: 'PROTECT' },
  { path: '/approvals', label: 'Approval Queue', icon: CircleCheck, group: 'PROTECT', roles: ['ADMIN', 'ANALYST'] },
  { path: '/audit', label: 'Audit Logs', icon: FileClock, group: 'MANAGE' },
  // Shown to administrators only. The server refuses everyone else in any case.
  { path: '/users', label: 'Users', icon: Users, group: 'MANAGE', roles: ['ADMIN'] },
  { path: '/settings', label: 'Settings', icon: Settings2, group: 'MANAGE' },
];

/** Whether a navigation item is offered to a role. Items without `roles` are for everyone. */
export function visibleTo(item: NavigationItem, role: Role | null | undefined): boolean {
  return !item.roles || (role != null && item.roles.includes(role));
}
