import { Component, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    this.props.onReset?.();
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      return (
        <div className="flex flex-col items-center justify-center min-h-[400px] p-8 text-center">
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center mb-4" style={{ background: "rgba(239,68,68,0.1)" }}>
            <AlertTriangle className="w-8 h-8" style={{ color: "#ef4444" }} />
          </div>
          <h2 className="text-xl font-bold mb-2">Something went wrong</h2>
          <p className="text-sm text-muted-foreground mb-6 max-w-md">
            {this.state.error?.message ?? "An unexpected error occurred. Please try again."}
          </p>
          <div className="flex gap-3">
            <Button variant="outline" onClick={() => window.location.reload()} className="gap-2">
              <RefreshCw className="w-4 h-4" /> Reload Page
            </Button>
            <Button onClick={this.handleReset} className="gap-2">
              Try Again
            </Button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
