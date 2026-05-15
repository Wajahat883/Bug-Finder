import { Link } from "wouter";
import { ShieldX, ArrowLeft, Home } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function Forbidden() {
  return (
    <div className="min-h-[80vh] flex flex-col items-center justify-center text-center px-4">
      <div className="mb-6 p-5 rounded-full bg-red-500/10 border border-red-500/20">
        <ShieldX className="w-14 h-14 text-red-400" />
      </div>
      <h1 className="text-4xl font-bold tracking-tight mb-2">Access Denied</h1>
      <p className="text-6xl font-mono font-black text-red-500/30 my-4">403</p>
      <p className="text-muted-foreground max-w-md mb-8">
        You don't have permission to view this page. Contact your administrator if you believe this is a mistake.
      </p>
      <div className="flex gap-3">
        <Button variant="outline" onClick={() => window.history.back()} className="gap-2">
          <ArrowLeft className="w-4 h-4" /> Go Back
        </Button>
        <Link href="/">
          <Button className="gap-2">
            <Home className="w-4 h-4" /> Dashboard
          </Button>
        </Link>
      </div>
    </div>
  );
}
