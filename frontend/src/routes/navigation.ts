import { Activity, Bot, CircleCheck, Database, FileClock, LayoutDashboard, ScanLine, Settings2, ShieldCheck, Waypoints } from 'lucide-react';

export const navigation = [
  { path: '/', label: 'Overview', icon: LayoutDashboard, group: 'WORKSPACE' },
  { path: '/connections', label: 'Connections', icon: Database, group: 'DISCOVER' },
  { path: '/schema', label: 'Schema Explorer', icon: Waypoints, group: 'DISCOVER' },
  { path: '/scans', label: 'Scan Results', icon: ScanLine, group: 'DISCOVER' },
  { path: '/classifications', label: 'AI Classification', icon: Bot, group: 'PROTECT' },
  { path: '/policies', label: 'Masking Policies', icon: ShieldCheck, group: 'PROTECT' },
  { path: '/approvals', label: 'Approval Queue', icon: CircleCheck, group: 'PROTECT' },
  { path: '/audit', label: 'Audit Logs', icon: FileClock, group: 'MANAGE' },
  { path: '/settings', label: 'Settings', icon: Settings2, group: 'MANAGE' },
];

export const upcomingPages = [
  { path: '/classifications', title: 'AI Classification', icon: Bot, eyebrow: 'CONTEXT FOR EVERY FINDING', heading: 'Turn findings into decisions', description: 'Review AI-assisted classifications and protection recommendations, with the final decision always in your hands.', next: 'AI recommendations follow the scanning phase.' },
  { path: '/policies', title: 'Masking Policies', icon: ShieldCheck, eyebrow: 'PROTECTION WITH PURPOSE', heading: 'Define the right protection', description: 'Create and preview masking policies that protect sensitive data while preserving your source records.', next: 'Policy creation and previews will be available in the masking phase.' },
  { path: '/approvals', title: 'Approval Queue', icon: CircleCheck, eyebrow: 'HUMAN REVIEW, ALWAYS', heading: 'Every protection gets a review', description: 'Approve a specific policy version before separately choosing to deploy it.', next: 'Policy approvals will become available with masking policies.' },
  { path: '/audit', title: 'Audit Logs', icon: FileClock, eyebrow: 'A CLEAR RECORD', heading: 'Know what changed, and when', description: 'Review the history of discovery, policy decisions, and protection deployments in one place.', next: 'The searchable activity timeline is planned for the audit phase.' },
  { path: '/settings', title: 'Settings', icon: Activity, eyebrow: 'YOUR WORKSPACE', heading: 'Built around your workflow', description: 'Manage workspace preferences and review your privacy services as the workspace grows.', next: 'Workspace settings are planned for a later phase.' },
];
