import { Component, type ErrorInfo, type ReactNode } from 'react';

/** Keeps a crash inside one page from blanking the whole workspace. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean }> {
  state = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('PrivacyShield view error', error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return <div className="page-content"><section className="panel empty-feature" role="alert">
        <h1>Something went wrong</h1>
        <p>This view ran into an unexpected problem. Reloading usually brings your workspace back.</p>
        <button type="button" className="button primary" onClick={() => window.location.reload()}>Reload the workspace</button>
      </section></div>;
    }
    return this.props.children;
  }
}
