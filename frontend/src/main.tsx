import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
// Fonts are bundled with the application: the Content-Security-Policy allows no other origin.
import '@fontsource-variable/bricolage-grotesque/index.css';
import '@fontsource/ibm-plex-sans/latin-400.css';
import '@fontsource/ibm-plex-sans/latin-500.css';
import '@fontsource/ibm-plex-sans/latin-600.css';
import '@fontsource/ibm-plex-mono/latin-400.css';
import '@fontsource/ibm-plex-mono/latin-500.css';
// Order matters: tokens and shared pieces first, the feature stylesheet next, page layouts last.
import './theme/tokens.css';
import './theme/base.css';
import './theme/components.css';
import './theme/shell.css';
import './styles.css';
import './theme/dashboard.css';
import './theme/policies.css';
import './theme/users.css';

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
