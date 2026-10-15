import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

/**
 * Error Boundary Component
 * 
 * Catches JavaScript errors anywhere in the child component tree,
 * logs those errors, and displays a fallback UI instead of crashing.
 * 
 * Why: Prevents the entire app from crashing due to errors in individual components
 */
class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null
  };public static getDerivedStateFromError(error: Error): State {
      return { hasError: true, error, errorInfo: null };
    }
  
    public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
      console.error('ErrorBoundary caught an error:', error, errorInfo);
      
      this.setState({
        error,
        errorInfo
      });
    }
  
    private handleReset = () => {
      this.setState({
        hasError: false,
        error: null,
        errorInfo: null
      });
      
      window.location.reload();
    };
  public render() {
    if (this.state.hasError) {
      const isDev = (import.meta as any).env?.DEV || false;
      
      return (
        <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
          <div className="max-w-2xl w-full bg-white rounded-lg shadow-lg p-8">
            <div className="flex items-center gap-4 mb-6">
              <div className="p-3 bg-red-100 rounded-full">
                <AlertTriangle className="w-8 h-8 text-red-600" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Something went wrong</h1>
                <p className="text-gray-600 mt-1">The application encountered an unexpected error</p>
              </div>
            </div>

            {this.state.error && (
              <div className="mb-6">
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <h2 className="text-sm font-semibold text-red-900 mb-2">Error Details:</h2>
                  <p className="text-sm text-red-800 font-mono">
                    {this.state.error.toString()}
                  </p>
                </div>
              </div>
            )}

            {this.state.errorInfo && isDev && (
              <details className="mb-6">
                <summary className="text-sm font-semibold text-gray-700 cursor-pointer hover:text-gray-900">
                  Stack Trace (Development Only)
                </summary>
                <pre className="mt-2 text-xs bg-gray-100 p-4 rounded-lg overflow-auto max-h-64">
                  {this.state.errorInfo.componentStack}
                </pre>
              </details>
            )}
