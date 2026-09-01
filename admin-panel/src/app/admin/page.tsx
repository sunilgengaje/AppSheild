'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function SecretAdminRedirectPage() {
  const router = useRouter();

  useEffect(() => {
    router.replace('/?mode=admin');
  }, [router]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans flex items-center justify-center">
      <div className="text-center space-y-4">
        <div className="w-12 h-12 bg-indigo-600/20 border border-indigo-500/30 text-indigo-400 rounded-2xl flex items-center justify-center font-bold text-2xl mx-auto animate-pulse">
          🛡️
        </div>
        <p className="text-slate-400 text-sm font-mono">Redirecting to Secure Admin Control Plane...</p>
      </div>
    </div>
  );
}
