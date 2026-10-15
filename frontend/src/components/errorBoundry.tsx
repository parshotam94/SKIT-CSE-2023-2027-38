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
  