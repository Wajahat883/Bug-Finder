import { cn } from "@/lib/utils";

function Pulse({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-md bg-muted/50", className)} />;
}

export function PageSkeleton() {
  return (
    <div className="space-y-6 p-6">
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <Pulse className="h-8 w-48" />
          <Pulse className="h-4 w-72" />
        </div>
        <Pulse className="h-10 w-32" />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="rounded-xl border border-border p-5 space-y-2">
            <Pulse className="h-3 w-20" />
            <Pulse className="h-7 w-16" />
          </div>
        ))}
      </div>
      <div className="rounded-xl border border-border p-5 space-y-3">
        <Pulse className="h-4 w-32" />
        {[...Array(5)].map((_, i) => (
          <div key={i} className="flex gap-4">
            <Pulse className="h-4 w-16" />
            <Pulse className="h-4 flex-1" />
            <Pulse className="h-4 w-24" />
          </div>
        ))}
      </div>
    </div>
  );
}

export function CardSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="rounded-xl border border-border p-5 space-y-3">
      <Pulse className="h-4 w-24" />
      {[...Array(lines)].map((_, i) => (
        <Pulse key={i} className="h-3 w-full" style={{ width: `${100 - i * 15}%` }} />
      ))}
    </div>
  );
}

export function TableSkeleton({ rows = 8, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="rounded-xl border border-border overflow-hidden">
      <div className="flex gap-4 p-4 border-b border-border">
        {[...Array(cols)].map((_, i) => (
          <Pulse key={i} className="h-4" style={{ width: `${60 + i * 20}px` }} />
        ))}
      </div>
      {[...Array(rows)].map((_, i) => (
        <div key={i} className="flex gap-4 p-4 border-b border-border/50">
          {[...Array(cols)].map((_, j) => (
            <Pulse key={j} className="h-3" style={{ width: `${40 + j * 30}px` }} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function DetailSkeleton() {
  return (
    <div className="space-y-6 p-6">
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <Pulse className="h-8 w-64" />
          <div className="flex gap-2">
            <Pulse className="h-5 w-16" />
            <Pulse className="h-5 w-24" />
            <Pulse className="h-5 w-20" />
          </div>
        </div>
        <div className="flex gap-2">
          <Pulse className="h-9 w-28" />
          <Pulse className="h-9 w-28" />
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <CardSkeleton lines={5} />
        <CardSkeleton lines={3} />
      </div>
      <CardSkeleton lines={8} />
    </div>
  );
}
