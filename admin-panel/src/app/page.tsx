import React from 'react';

export default function AppShieldDashboard() {
  return (
    <div className="min-h-screen bg-slate-900 text-white font-sans p-8">
      <div className="max-w-6xl mx-auto">
        <header className="flex justify-between items-center mb-12">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-indigo-500 rounded-lg flex items-center justify-center font-bold text-xl">🛡️</div>
            <h1 className="text-2xl font-bold tracking-tight">AppShield SaaS</h1>
          </div>
          <button className="bg-indigo-600 hover:bg-indigo-700 transition px-6 py-2 rounded-lg font-medium shadow-lg shadow-indigo-500/20">
            Sign In
          </button>
        </header>

        <main className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* Main Stats / Welcome */}
          <div className="col-span-1 md:col-span-2 bg-slate-800 rounded-2xl p-8 border border-slate-700 shadow-xl">
            <h2 className="text-3xl font-semibold mb-4">Protect Your Mobile Users</h2>
            <p className="text-slate-400 mb-8 max-w-lg leading-relaxed">
              Integrate military-grade RASP and AI Fraud defense into your Android and iOS applications with zero-touch compilation.
            </p>
            
            <div className="bg-slate-900 rounded-xl p-6 border border-slate-700 mb-6">
              <h3 className="text-sm uppercase text-slate-500 font-semibold tracking-wider mb-3">Your Integration Key</h3>
              <code className="text-emerald-400 font-mono bg-slate-950 px-4 py-2 rounded border border-emerald-900/30 block">
                SHIELD-a9b8c7d6-test-trial-key
              </code>
            </div>
            
            <button className="w-full bg-slate-100 text-slate-900 hover:bg-white transition px-6 py-3 rounded-lg font-bold shadow-xl">
              Download SDK (.aar & .jar)
            </button>
          </div>

          {/* Pricing / Tiers */}
          <div className="col-span-1 flex flex-col gap-4">
            <div className="bg-slate-800 rounded-2xl p-6 border border-indigo-500/30 relative overflow-hidden group">
              <div className="absolute top-0 right-0 bg-indigo-500 text-xs font-bold px-3 py-1 rounded-bl-lg">ACTIVE</div>
              <h3 className="text-xl font-bold mb-2 text-indigo-400">Trial Tier</h3>
              <p className="text-slate-400 text-sm mb-4">30 days of basic protection.</p>
              <ul className="text-sm space-y-2 text-slate-300">
                <li className="flex gap-2"><span>✅</span> Root Detection</li>
                <li className="flex gap-2"><span>✅</span> Emulator Detection</li>
                <li className="flex gap-2 text-slate-600"><span>❌</span> Frida Detection</li>
              </ul>
            </div>

            <div className="bg-slate-800 rounded-2xl p-6 border border-amber-500/30">
              <h3 className="text-xl font-bold mb-2 text-amber-400">Gold Tier</h3>
              <p className="text-slate-400 text-sm mb-4">$499/mo for full enterprise defense.</p>
              <ul className="text-sm space-y-2 text-slate-300 mb-6">
                <li className="flex gap-2"><span>✅</span> Advanced Hooking Defenses</li>
                <li className="flex gap-2"><span>✅</span> AI Liveness Checks</li>
                <li className="flex gap-2"><span>✅</span> Network Pinning</li>
              </ul>
              <button className="w-full bg-amber-500 hover:bg-amber-400 text-slate-900 transition px-4 py-2 rounded-lg font-bold shadow-lg shadow-amber-500/20">
                Upgrade with Stripe
              </button>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
