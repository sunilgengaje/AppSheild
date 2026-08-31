'use client';

import React, { useState, useEffect } from 'react';

type UserRole = 'PUBLIC' | 'SUPER_ADMIN' | 'CLIENT';
type SubTab = 'PIPELINE' | 'PROVISION' | 'GLOBAL_THREATS' | 'CLIENT_OVERVIEW' | 'CLIENT_SDK' | 'CLIENT_DOCS' | 'CLIENT_THREATS';

export default function AppShieldEnterprisePortal() {
  const [role, setRole] = useState<UserRole>('PUBLIC');
  const [activeTab, setActiveTab] = useState<SubTab>('PIPELINE');
  const [authToken, setAuthToken] = useState<string>('');
  const [userInfo, setUserInfo] = useState<{ username: string; company_name: string; app_id: string } | null>(null);

  // Login Modal State
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [loginRole, setLoginRole] = useState<'SUPER_ADMIN' | 'CLIENT'>('SUPER_ADMIN');
  const [loginUsername, setLoginUsername] = useState('admin');
  const [loginPassword, setLoginPassword] = useState('admin123');
  const [loginError, setLoginError] = useState('');

  // Lead / Quote Form Modal
  const [showQuoteModal, setShowQuoteModal] = useState(false);
  const [quoteCompany, setQuoteCompany] = useState('');
  const [quoteEmail, setQuoteEmail] = useState('');
  const [quotePhone, setQuotePhone] = useState('');
  const [quoteTier, setQuoteTier] = useState('GOLD');
  const [quoteNotes, setQuoteNotes] = useState('');
  const [quoteSuccess, setQuoteSuccess] = useState('');

  // Admin Provisioning State
  const [provUsername, setProvUsername] = useState('');
  const [provPassword, setProvPassword] = useState('');
  const [provCompany, setProvCompany] = useState('');
  const [provEmail, setProvEmail] = useState('');
  const [provAppId, setProvAppId] = useState('');
  const [provTier, setProvTier] = useState('GOLD');
  const [provValidFrom, setProvValidFrom] = useState(new Date().toISOString().split('T')[0]);
  const [provValidTo, setProvValidTo] = useState(
    new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
  );
  const [provSuccess, setProvSuccess] = useState('');
  const [provError, setProvError] = useState('');

  // Client Dashboard State
  const [clientData, setClientData] = useState<{
    company_name: string;
    app_id: string;
    license: {
      license_key: string;
      tier: string;
      valid_from: string;
      valid_to: string;
      features: string[];
    };
    recent_threats: Array<{ id: number; threat: string; device_id: string; confidence: number; timestamp: number }>;
  } | null>(null);

  // Admin Leads Pipeline Data
  const [leadsList, setLeadsList] = useState<Array<{
    id: number;
    company_name: string;
    email: string;
    phone?: string;
    package_tier: string;
    status: string;
    notes?: string;
  }>>([]);

  const API_BASE = 'https://appshield-backend-lupg.onrender.com';

  // Handle Login
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError('');
    try {
      const res = await fetch(`${API_BASE}/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginUsername, password: loginPassword })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Login failed');
      }

      setAuthToken(data.access_token);
      setUserInfo({ username: data.username, company_name: data.company_name, app_id: data.app_id });
      setShowLoginModal(false);

      if (data.role === 'SUPER_ADMIN') {
        setRole('SUPER_ADMIN');
        setActiveTab('PIPELINE');
        fetchLeads(data.access_token);
      } else {
        setRole('CLIENT');
        setActiveTab('CLIENT_OVERVIEW');
        fetchClientDashboard(data.access_token);
      }
    } catch (err: any) {
      setLoginError(err.message);
    }
  };

  // Fetch Sales Pipeline Leads
  const fetchLeads = async (token: string) => {
    try {
      const res = await fetch(`${API_BASE}/v1/admin/quotes`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setLeadsList(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Fetch Client Dashboard Data
  const fetchClientDashboard = async (token: string) => {
    try {
      const res = await fetch(`${API_BASE}/v1/client/dashboard`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setClientData(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Submit Public Quote Request
  const handleQuoteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setQuoteSuccess('');
    try {
      const res = await fetch(`${API_BASE}/v1/quotes/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          company_name: quoteCompany,
          email: quoteEmail,
          phone: quotePhone,
          package_tier: quoteTier,
          notes: quoteNotes
        })
      });
      const data = await res.json();
      if (res.ok) {
        setQuoteSuccess(data.message);
        setTimeout(() => {
          setShowQuoteModal(false);
          setQuoteSuccess('');
          setQuoteCompany('');
          setQuoteEmail('');
        }, 3000);
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Admin Client Provisioning
  const handleProvisionClient = async (e: React.FormEvent) => {
    e.preventDefault();
    setProvSuccess('');
    setProvError('');
    try {
      const res = await fetch(`${API_BASE}/v1/admin/clients/provision`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`
        },
        body: JSON.stringify({
          username: provUsername,
          password: provPassword,
          company_name: provCompany,
          email: provEmail,
          app_id: provAppId,
          package_tier: provTier,
          valid_from: provValidFrom,
          valid_to: provValidTo
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Provisioning failed');

      setProvSuccess(`✅ Account & License Provisioned! Key: ${data.license_key}`);
      setProvUsername('');
      setProvPassword('');
      setProvCompany('');
      setProvAppId('');
    } catch (err: any) {
      setProvError(err.message);
    }
  };

  // Update Lead Status
  const handleUpdateLeadStatus = async (quoteId: number, newStatus: string) => {
    try {
      const res = await fetch(`${API_BASE}/v1/admin/quotes/update-status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`
        },
        body: JSON.stringify({ quote_id: quoteId, status: newStatus })
      });
      if (res.ok) {
        fetchLeads(authToken);
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Logout
  const handleLogout = () => {
    setRole('PUBLIC');
    setAuthToken('');
    setUserInfo(null);
    setClientData(null);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-indigo-500 selection:text-white">
      {/* Top Glass Navigation */}
      <nav className="border-b border-slate-800 bg-slate-900/60 backdrop-blur-xl sticky top-0 z-40 px-8 py-4 flex justify-between items-center shadow-2xl">
        <div className="flex items-center gap-3 cursor-pointer" onClick={() => setRole('PUBLIC')}>
          <div className="w-10 h-10 bg-gradient-to-tr from-indigo-600 to-emerald-400 rounded-xl flex items-center justify-center font-black text-xl shadow-lg shadow-indigo-500/30">
            🛡️
          </div>
          <div>
            <span className="text-xl font-bold tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
              AppShield SaaS
            </span>
            <span className="block text-[10px] uppercase tracking-widest text-emerald-400 font-bold">
              Enterprise Control Plane
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {role === 'PUBLIC' ? (
            <>
              <button
                onClick={() => setShowQuoteModal(true)}
                className="hidden sm:block border border-slate-700 hover:border-slate-500 bg-slate-800/80 text-slate-200 px-5 py-2 rounded-xl text-sm font-semibold transition shadow-md"
              >
                Request Quotation
              </button>
              <button
                onClick={() => {
                  setLoginRole('CLIENT');
                  setShowLoginModal(true);
                }}
                className="bg-gradient-to-r from-indigo-600 to-emerald-500 hover:opacity-90 text-white px-6 py-2 rounded-xl text-sm font-bold shadow-lg shadow-indigo-500/25 transition"
              >
                Sign In to Portal
              </button>
            </>
          ) : (
            <div className="flex items-center gap-4">
              <div className="text-right hidden sm:block">
                <span className="block text-xs font-bold text-slate-400">{userInfo?.company_name}</span>
                <span className="text-xs font-mono text-emerald-400">
                  {role === 'SUPER_ADMIN' ? '👑 SUPER ADMIN' : `💼 ${userInfo?.username}`}
                </span>
              </div>
              <button
                onClick={handleLogout}
                className="bg-rose-500/10 border border-rose-500/30 text-rose-400 hover:bg-rose-500/20 px-4 py-2 rounded-xl text-xs font-bold transition"
              >
                Sign Out
              </button>
            </div>
          )}
        </div>
      </nav>

      {/* PUBLIC LANDING PAGE */}
      {role === 'PUBLIC' && (
        <div className="max-w-7xl mx-auto px-6 py-12">
          {/* Hero Section */}
          <div className="text-center py-16 px-6 rounded-3xl bg-gradient-to-b from-slate-900 to-slate-950 border border-slate-800 shadow-2xl relative overflow-hidden mb-16">
            <div className="absolute -top-32 -left-32 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl"></div>
            <div className="absolute -bottom-32 -right-32 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl"></div>

            <span className="inline-block bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 text-xs font-bold px-4 py-1.5 rounded-full uppercase tracking-widest mb-6">
              Enterprise Mobile RASP & Fraud Defense
            </span>
            <h1 className="text-4xl md:text-6xl font-black tracking-tight max-w-4xl mx-auto leading-tight mb-6">
              Protect Your Mobile Apps Against Frida, Root, and AI Banking Fraud
            </h1>
            <p className="text-slate-400 text-lg max-w-2xl mx-auto mb-10 leading-relaxed">
              Zero-touch Kotlin & C++ Security Engine for Android. Turn key hardware security, automated license management, and real-time cloud threat intelligence.
            </p>

            <div className="flex flex-wrap justify-center gap-4">
              <button
                onClick={() => setShowQuoteModal(true)}
                className="bg-gradient-to-r from-indigo-600 to-emerald-500 hover:scale-105 transition transform px-8 py-4 rounded-2xl font-bold text-white shadow-xl shadow-indigo-500/20 text-base"
              >
                Schedule Demo & Get Quote ➔
              </button>
              <button
                onClick={() => {
                  setLoginRole('SUPER_ADMIN');
                  setLoginUsername('admin');
                  setLoginPassword('admin123');
                  setShowLoginModal(true);
                }}
                className="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 px-8 py-4 rounded-2xl font-bold transition text-base"
              >
                Super Admin Portal Demo
              </button>
            </div>
          </div>

          {/* Pricing & Feature Matrix */}
          <h2 className="text-3xl font-bold text-center mb-12">Enterprise Tier Matrix</h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {/* Trial Tier */}
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 flex flex-col justify-between">
              <div>
                <h3 className="text-xl font-bold text-slate-300 mb-2">Trial Tier</h3>
                <p className="text-slate-400 text-xs mb-6">30-day evaluation package for mobile dev teams.</p>
                <div className="text-3xl font-black mb-6">$0 <span className="text-xs text-slate-500 font-normal">/ 30 days</span></div>
                <ul className="space-y-3 text-xs text-slate-300">
                  <li className="flex gap-2"><span>✅</span> Root & Su Binary Detection</li>
                  <li className="flex gap-2"><span>✅</span> QEMU / AVD Emulator Check</li>
                  <li className="flex gap-2"><span>✅</span> Debugger & TracerPid Check</li>
                  <li className="flex gap-2 text-slate-600"><span>❌</span> Frida Memory Scanner</li>
                  <li className="flex gap-2 text-slate-600"><span>❌</span> LSPosed & Xposed Defense</li>
                </ul>
              </div>
              <button
                onClick={() => setShowQuoteModal(true)}
                className="w-full mt-8 bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 rounded-xl text-xs transition"
              >
                Evaluate Trial
              </button>
            </div>

            {/* Bronze Tier */}
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 flex flex-col justify-between">
              <div>
                <h3 className="text-xl font-bold text-amber-400 mb-2">Bronze Tier</h3>
                <p className="text-slate-400 text-xs mb-6">Standard defense for single consumer mobile apps.</p>
                <div className="text-3xl font-black mb-6">$199 <span className="text-xs text-slate-500 font-normal">/ month</span></div>
                <ul className="space-y-3 text-xs text-slate-300">
                  <li className="flex gap-2"><span>✅</span> Root & Magisk Detection</li>
                  <li className="flex gap-2"><span>✅</span> Hardware-level Emulator Check</li>
                  <li className="flex gap-2"><span>✅</span> Debugger & JDWP Timing</li>
                  <li className="flex gap-2"><span>✅</span> Frida Memory & Port Scanner</li>
                  <li className="flex gap-2 text-slate-600"><span>❌</span> LSPosed & Xposed Defense</li>
                </ul>
              </div>
              <button
                onClick={() => setShowQuoteModal(true)}
                className="w-full mt-8 bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 rounded-xl text-xs transition"
              >
                Request Bronze
              </button>
            </div>

            {/* Silver Tier */}
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 flex flex-col justify-between">
              <div>
                <h3 className="text-xl font-bold text-slate-200 mb-2">Silver Tier</h3>
                <p className="text-slate-400 text-xs mb-6">Enhanced security for fintech & healthcare apps.</p>
                <div className="text-3xl font-black mb-6">$399 <span className="text-xs text-slate-500 font-normal">/ month</span></div>
                <ul className="space-y-3 text-xs text-slate-300">
                  <li className="flex gap-2"><span>✅</span> All Bronze Tier Features</li>
                  <li className="flex gap-2"><span>✅</span> LSPosed / Xposed Hook Defense</li>
                  <li className="flex gap-2"><span>✅</span> Suspicious Overlay Defense</li>
                  <li className="flex gap-2"><span>✅</span> SMS Interceptor Guard</li>
                  <li className="flex gap-2 text-slate-600"><span>❌</span> AI Behavior Analytics</li>
                </ul>
              </div>
              <button
                onClick={() => setShowQuoteModal(true)}
                className="w-full mt-8 bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 rounded-xl text-xs transition"
              >
                Request Silver
              </button>
            </div>

            {/* Gold Tier - Highlighted */}
            <div className="bg-gradient-to-b from-indigo-900/40 to-slate-900 border-2 border-emerald-500/50 rounded-3xl p-6 flex flex-col justify-between relative shadow-2xl shadow-emerald-500/10">
              <div className="absolute top-0 right-0 bg-emerald-500 text-slate-950 font-black text-[10px] uppercase px-3 py-1 rounded-bl-xl tracking-wider">
                RECOMMENDED
              </div>
              <div>
                <h3 className="text-xl font-bold text-emerald-400 mb-2">Gold Tier</h3>
                <p className="text-slate-400 text-xs mb-6">Complete military-grade B2B defense suite.</p>
                <div className="text-3xl font-black mb-6">$899 <span className="text-xs text-slate-500 font-normal">/ month</span></div>
                <ul className="space-y-3 text-xs text-slate-300">
                  <li className="flex gap-2"><span>✅</span> Full RASP Defense (Frida, Root, Zygisk)</li>
                  <li className="flex gap-2"><span>✅</span> AI Behavior & Touch Pressure Guard</li>
                  <li className="flex gap-2"><span>✅</span> NFC Relay Timing & Sensor Anomaly</li>
                  <li className="flex gap-2"><span>✅</span> Vishing Call & Overlay Defense</li>
                  <li className="flex gap-2"><span>✅</span> Dedicated Account Manager & SLA</li>
                </ul>
              </div>
              <button
                onClick={() => setShowQuoteModal(true)}
                className="w-full mt-8 bg-gradient-to-r from-emerald-500 to-indigo-600 hover:opacity-90 text-white font-bold py-3 rounded-xl text-xs transition shadow-lg shadow-emerald-500/20"
              >
                Request Gold Quote
              </button>
            </div>
          </div>
        </div>
      )}

      {/* SUPER ADMIN WORKSPACE */}
      {role === 'SUPER_ADMIN' && (
        <div className="max-w-7xl mx-auto px-6 py-8">
          {/* Sub Navigation */}
          <div className="flex gap-4 border-b border-slate-800 pb-4 mb-8">
            <button
              onClick={() => setActiveTab('PIPELINE')}
              className={`px-5 py-2.5 rounded-xl text-xs font-bold transition ${
                activeTab === 'PIPELINE' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
              }`}
            >
              💼 Sales Pipeline ({leadsList.length})
            </button>
            <button
              onClick={() => setActiveTab('PROVISION')}
              className={`px-5 py-2.5 rounded-xl text-xs font-bold transition ${
                activeTab === 'PROVISION' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
              }`}
            >
              🔑 Client Provisioner & License Creator
            </button>
          </div>

          {/* PIPELINE TAB */}
          {activeTab === 'PIPELINE' && (
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
              <h2 className="text-2xl font-bold mb-6">Quotation & Demo Request Pipeline</h2>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                    <tr>
                      <th className="p-4">ID</th>
                      <th className="p-4">Company</th>
                      <th className="p-4">Email / Phone</th>
                      <th className="p-4">Target Tier</th>
                      <th className="p-4">Status</th>
                      <th className="p-4">Pipeline Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {leadsList.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="p-6 text-center text-slate-500">
                          No quotation requests submitted yet.
                        </td>
                      </tr>
                    ) : (
                      leadsList.map((lead) => (
                        <tr key={lead.id} className="hover:bg-slate-850/50 transition">
                          <td className="p-4 font-mono font-bold text-indigo-400">#{lead.id}</td>
                          <td className="p-4 font-semibold text-white">{lead.company_name}</td>
                          <td className="p-4">{lead.email} {lead.phone && `• ${lead.phone}`}</td>
                          <td className="p-4">
                            <span className="bg-amber-500/10 border border-amber-500/30 text-amber-400 px-3 py-1 rounded-full font-bold text-[10px]">
                              {lead.package_tier}
                            </span>
                          </td>
                          <td className="p-4">
                            <span className={`px-3 py-1 rounded-full font-bold text-[10px] ${
                              lead.status === 'NEW' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/30' :
                              lead.status === 'DEMO_SCHEDULED' ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30' :
                              lead.status === 'QUOTATION_SENT' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30' :
                              lead.status === 'PO_RECEIVED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' :
                              'bg-slate-700 text-slate-300'
                            }`}>
                              {lead.status}
                            </span>
                          </td>
                          <td className="p-4">
                            <div className="flex gap-2">
                              {lead.status === 'NEW' && (
                                <button
                                  onClick={() => handleUpdateLeadStatus(lead.id, 'DEMO_SCHEDULED')}
                                  className="bg-sky-600 hover:bg-sky-500 text-white px-3 py-1 rounded-lg text-[10px] font-bold"
                                >
                                  Schedule Demo
                                </button>
                              )}
                              {lead.status === 'DEMO_SCHEDULED' && (
                                <button
                                  onClick={() => handleUpdateLeadStatus(lead.id, 'QUOTATION_SENT')}
                                  className="bg-amber-600 hover:bg-amber-500 text-white px-3 py-1 rounded-lg text-[10px] font-bold"
                                >
                                  Send Final Quote
                                </button>
                              )}
                              {lead.status === 'QUOTATION_SENT' && (
                                <button
                                  onClick={() => handleUpdateLeadStatus(lead.id, 'PO_RECEIVED')}
                                  className="bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1 rounded-lg text-[10px] font-bold"
                                >
                                  Mark PO Received
                                </button>
                              )}
                              {lead.status === 'PO_RECEIVED' && (
                                <button
                                  onClick={() => {
                                    setProvCompany(lead.company_name);
                                    setProvEmail(lead.email);
                                    setProvTier(lead.package_tier);
                                    setProvAppId(`com.${lead.company_name.toLowerCase().replace(/[^a-z0-9]/g, '')}.app`);
                                    setProvUsername(lead.company_name.toLowerCase().replace(/[^a-z0-9]/g, '') + '_admin');
                                    setProvPassword('ClientPass123!');
                                    setActiveTab('PROVISION');
                                  }}
                                  className="bg-gradient-to-r from-emerald-500 to-indigo-600 text-white px-3 py-1 rounded-lg text-[10px] font-bold shadow-lg"
                                >
                                  Provision Account ➔
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* PROVISION TAB */}
          {activeTab === 'PROVISION' && (
            <div className="max-w-2xl mx-auto bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
              <h2 className="text-2xl font-bold mb-2">B2B Account & License Provisioner</h2>
              <p className="text-slate-400 text-xs mb-6">
                Generate client portal credentials, assign package tier, and set active validity date range.
              </p>

              {provSuccess && <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-4 rounded-xl text-xs mb-6 font-mono">{provSuccess}</div>}
              {provError && <div className="bg-rose-500/10 border border-rose-500/30 text-rose-400 p-4 rounded-xl text-xs mb-6">{provError}</div>}

              <form onSubmit={handleProvisionClient} className="space-y-4 text-xs">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-slate-400 font-semibold mb-1">Company Name</label>
                    <input
                      type="text"
                      required
                      value={provCompany}
                      onChange={(e) => setProvCompany(e.target.value)}
                      placeholder="e.g. Acme Banking Corp"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 font-semibold mb-1">Target App ID</label>
                    <input
                      type="text"
                      required
                      value={provAppId}
                      onChange={(e) => setProvAppId(e.target.value)}
                      placeholder="e.g. com.acmebank.mobile"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500 font-mono"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-slate-400 font-semibold mb-1">Client Username</label>
                    <input
                      type="text"
                      required
                      value={provUsername}
                      onChange={(e) => setProvUsername(e.target.value)}
                      placeholder="e.g. acme_admin"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 font-semibold mb-1">Client Password</label>
                    <input
                      type="text"
                      required
                      value={provPassword}
                      onChange={(e) => setProvPassword(e.target.value)}
                      placeholder="Assign strong password"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <label className="block text-slate-400 font-semibold mb-1">Assigned Tier</label>
                    <select
                      value={provTier}
                      onChange={(e) => setProvTier(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                    >
                      <option value="TRIAL">Trial Tier</option>
                      <option value="BRONZE">Bronze Tier</option>
                      <option value="SILVER">Silver Tier</option>
                      <option value="GOLD">Gold Tier</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-slate-400 font-semibold mb-1">Valid From (Date)</label>
                    <input
                      type="date"
                      required
                      value={provValidFrom}
                      onChange={(e) => setProvValidFrom(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 font-semibold mb-1">Valid To (Date)</label>
                    <input
                      type="date"
                      required
                      value={provValidTo}
                      onChange={(e) => setProvValidTo(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  className="w-full bg-gradient-to-r from-emerald-500 to-indigo-600 text-white font-bold py-3.5 rounded-xl shadow-xl shadow-emerald-500/20 text-sm mt-4"
                >
                  Issue License & Activate Account ➔
                </button>
              </form>
            </div>
          )}
        </div>
      )}

      {/* CLIENT PORTAL WORKSPACE */}
      {role === 'CLIENT' && (
        <div className="max-w-7xl mx-auto px-6 py-8">
          {/* Client Sub Nav */}
          <div className="flex gap-4 border-b border-slate-800 pb-4 mb-8">
            <button
              onClick={() => setActiveTab('CLIENT_OVERVIEW')}
              className={`px-5 py-2.5 rounded-xl text-xs font-bold transition ${
                activeTab === 'CLIENT_OVERVIEW' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
              }`}
            >
              📋 License & Renewal Status
            </button>
            <button
              onClick={() => setActiveTab('CLIENT_SDK')}
              className={`px-5 py-2.5 rounded-xl text-xs font-bold transition ${
                activeTab === 'CLIENT_SDK' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
              }`}
            >
              📦 Gated SDK Binaries (.aar / .jar)
            </button>
            <button
              onClick={() => setActiveTab('CLIENT_DOCS')}
              className={`px-5 py-2.5 rounded-xl text-xs font-bold transition ${
                activeTab === 'CLIENT_DOCS' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
              }`}
            >
              📖 Authorized Integration Docs
            </button>
            <button
              onClick={() => setActiveTab('CLIENT_THREATS')}
              className={`px-5 py-2.5 rounded-xl text-xs font-bold transition ${
                activeTab === 'CLIENT_THREATS' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
              }`}
            >
              🚨 App Threat Telemetry
            </button>
          </div>

          {/* OVERVIEW TAB */}
          {activeTab === 'CLIENT_OVERVIEW' && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              <div className="col-span-2 bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
                <div className="flex justify-between items-center mb-6">
                  <div>
                    <h2 className="text-2xl font-bold text-white mb-1">{clientData?.company_name || userInfo?.company_name}</h2>
                    <span className="text-xs font-mono text-slate-400">Target App ID: {clientData?.app_id}</span>
                  </div>
                  <span className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-4 py-1.5 rounded-full text-xs font-black uppercase tracking-wider">
                    {clientData?.license?.tier || 'GOLD'} TIER ACTIVE
                  </span>
                </div>

                {/* License Key Box */}
                <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6 mb-8">
                  <span className="block text-[10px] uppercase font-bold text-slate-500 tracking-wider mb-2">
                    Your Authorized Production Integration Key
                  </span>
                  <code className="block bg-slate-900 text-emerald-400 font-mono text-sm px-4 py-3 rounded-xl border border-emerald-900/40 select-all">
                    {clientData?.license?.license_key || 'SHIELD-ACME-BANKING-GOLD-KEY'}
                  </code>
                </div>

                {/* Date Validity & Expiry */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                    <span className="block text-slate-500 text-xs font-semibold mb-1">Valid From (Start Date)</span>
                    <span className="text-lg font-bold text-slate-200">{clientData?.license?.valid_from || '2026-01-01'}</span>
                  </div>
                  <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                    <span className="block text-slate-500 text-xs font-semibold mb-1">Valid To (Expiration Date)</span>
                    <span className="text-lg font-bold text-emerald-400">{clientData?.license?.valid_to || '2027-01-01'}</span>
                  </div>
                </div>
              </div>

              {/* Renewal Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 flex flex-col justify-between">
                <div>
                  <h3 className="text-xl font-bold text-white mb-2">Subscription & Renewal</h3>
                  <p className="text-slate-400 text-xs mb-6">
                    Manage your annual B2B license renewal and add-on security feature modules.
                  </p>

                  <div className="space-y-3 mb-6">
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-400">Billing Status:</span>
                      <span className="text-emerald-400 font-bold">Paid (Invoice #INV-9021)</span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-400">Auto-Renew:</span>
                      <span className="text-slate-200 font-semibold">Enabled</span>
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => alert('Renewal request sent to your dedicated AppShield Enterprise Account Executive!')}
                  className="w-full bg-slate-800 hover:bg-slate-700 text-white font-bold py-3.5 rounded-xl text-xs transition border border-slate-700 shadow-xl"
                >
                  Request License Extension / Renewal
                </button>
              </div>
            </div>
          )}

          {/* GATED SDK BINARIES TAB */}
          {activeTab === 'CLIENT_SDK' && (
            <div className="max-w-4xl mx-auto bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
              <h2 className="text-2xl font-bold mb-2">Gated Enterprise SDK Downloads</h2>
              <p className="text-slate-400 text-xs mb-8">
                These binaries are protected and dynamically served only to authenticated B2B client sessions.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
                  <div>
                    <div className="w-12 h-12 bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 rounded-xl flex items-center justify-center font-bold text-xl mb-4">
                      📦
                    </div>
                    <h3 className="text-lg font-bold text-white mb-1">Android RASP Engine (.aar)</h3>
                    <p className="text-slate-400 text-xs mb-4">
                      Version 1.2.0 • Hardened Kotlin & C++ Native Binary (ARM64, x86_64).
                    </p>
                  </div>
                  <a
                    href={`${API_BASE}/v1/client/download/sdk?type=aar`}
                    className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3 rounded-xl text-xs text-center shadow-lg transition block"
                  >
                    Download shield-sdk-v1.2.0.aar
                  </a>
                </div>

                <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
                  <div>
                    <div className="w-12 h-12 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-xl flex items-center justify-center font-bold text-xl mb-4">
                      ⚙️
                    </div>
                    <h3 className="text-lg font-bold text-white mb-1">Gradle Plugin (.jar)</h3>
                    <p className="text-slate-400 text-xs mb-4">
                      Version 1.2.0 • Automated bytecode obfuscation and manifest injection.
                    </p>
                  </div>
                  <a
                    href={`${API_BASE}/v1/client/download/sdk?type=jar`}
                    className="w-full bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 rounded-xl text-xs text-center border border-slate-700 shadow-lg transition block"
                  >
                    Download shield-gradle-plugin-v1.2.0.jar
                  </a>
                </div>
              </div>
            </div>
          )}

          {/* AUTHORIZED INTEGRATION DOCS TAB */}
          {activeTab === 'CLIENT_DOCS' && (
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
              <h2 className="text-2xl font-bold mb-2">Authorized Integration Guide</h2>
              <p className="text-slate-400 text-xs mb-8">
                Restricted technical documentation for verified AppShield clients.
              </p>

              <div className="space-y-6 text-xs font-mono">
                {/* Step 1 */}
                <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6">
                  <h4 className="text-slate-200 font-bold text-sm mb-2 font-sans">1. Add .aar to App Build File (build.gradle.kts)</h4>
                  <pre className="bg-slate-900 p-4 rounded-xl text-emerald-400 overflow-x-auto">
{`dependencies {
    implementation(files("libs/shield-sdk-v1.2.0.aar"))
}`}
                  </pre>
                </div>

                {/* Step 2 */}
                <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6">
                  <h4 className="text-slate-200 font-bold text-sm mb-2 font-sans">2. Initialize SDK in Application.onCreate()</h4>
                  <pre className="bg-slate-900 p-4 rounded-xl text-indigo-300 overflow-x-auto">
{`class MainApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        AppShield.initialize(
            context = this,
            appId = "${clientData?.app_id || 'com.acmebank.mobile'}",
            licenseKey = "${clientData?.license?.license_key || 'SHIELD-ACME-BANKING-GOLD-KEY'}"
        )
    }
}`}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {/* CLIENT THREAT TELEMETRY TAB */}
          {activeTab === 'CLIENT_THREATS' && (
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
              <h2 className="text-2xl font-bold mb-6">Application Attack Telemetry Log</h2>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                    <tr>
                      <th className="p-4">Event ID</th>
                      <th className="p-4">Threat Type</th>
                      <th className="p-4">Device ID</th>
                      <th className="p-4">Confidence</th>
                      <th className="p-4">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {clientData?.recent_threats?.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="p-6 text-center text-slate-500">
                          No attack events recorded for this application.
                        </td>
                      </tr>
                    ) : (
                      clientData?.recent_threats?.map((t) => (
                        <tr key={t.id} className="hover:bg-slate-850/50 transition">
                          <td className="p-4 font-mono font-bold text-rose-400">#{t.id}</td>
                          <td className="p-4 font-bold text-white">{t.threat}</td>
                          <td className="p-4 font-mono text-slate-400">{t.device_id}</td>
                          <td className="p-4 text-emerald-400 font-bold">{t.confidence}%</td>
                          <td className="p-4 text-slate-500">{new Date(t.timestamp).toLocaleString()}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* LOGIN MODAL */}
      {showLoginModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 max-w-md w-full shadow-2xl relative">
            <button
              onClick={() => setShowLoginModal(false)}
              className="absolute top-4 right-4 text-slate-500 hover:text-white text-xl"
            >
              ✕
            </button>

            <h3 className="text-2xl font-bold text-white mb-2">Portal Authentication</h3>
            <p className="text-slate-400 text-xs mb-6">Select your portal mode and sign in.</p>

            {/* Role Selector Toggle */}
            <div className="grid grid-cols-2 gap-2 bg-slate-950 p-1.5 rounded-2xl mb-6 border border-slate-800">
              <button
                type="button"
                onClick={() => {
                  setLoginRole('SUPER_ADMIN');
                  setLoginUsername('admin');
                  setLoginPassword('admin123');
                }}
                className={`py-2 rounded-xl text-xs font-bold transition ${
                  loginRole === 'SUPER_ADMIN' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-white'
                }`}
              >
                👑 Super Admin
              </button>
              <button
                type="button"
                onClick={() => {
                  setLoginRole('CLIENT');
                  setLoginUsername('client_demo');
                  setLoginPassword('client123');
                }}
                className={`py-2 rounded-xl text-xs font-bold transition ${
                  loginRole === 'CLIENT' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-white'
                }`}
              >
                💼 Client Portal
              </button>
            </div>

            {loginError && <div className="bg-rose-500/10 border border-rose-500/30 text-rose-400 p-3 rounded-xl text-xs mb-4">{loginError}</div>}

            <form onSubmit={handleLogin} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 font-semibold mb-1">Username</label>
                <input
                  type="text"
                  required
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Password</label>
                <input
                  type="password"
                  required
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <button
                type="submit"
                className="w-full bg-gradient-to-r from-indigo-600 to-emerald-500 text-white font-bold py-3.5 rounded-xl text-xs transition shadow-lg shadow-indigo-500/20"
              >
                Sign In to {loginRole === 'SUPER_ADMIN' ? 'Admin Portal' : 'Client Dashboard'} ➔
              </button>
            </form>
          </div>
        </div>
      )}

      {/* QUOTATION MODAL */}
      {showQuoteModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 max-w-lg w-full shadow-2xl relative">
            <button
              onClick={() => setShowQuoteModal(false)}
              className="absolute top-4 right-4 text-slate-500 hover:text-white text-xl"
            >
              ✕
            </button>

            <h3 className="text-2xl font-bold text-white mb-2">Request Quotation & Demo</h3>
            <p className="text-slate-400 text-xs mb-6">Our enterprise sales engineering team will reach out with a custom quote.</p>

            {quoteSuccess && <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-4 rounded-xl text-xs mb-4">{quoteSuccess}</div>}

            <form onSubmit={handleQuoteSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 font-semibold mb-1">Company Name</label>
                <input
                  type="text"
                  required
                  value={quoteCompany}
                  onChange={(e) => setQuoteCompany(e.target.value)}
                  placeholder="e.g. Barclays / Revolut / Acme Health"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Work Email</label>
                  <input
                    type="email"
                    required
                    value={quoteEmail}
                    onChange={(e) => setQuoteEmail(e.target.value)}
                    placeholder="security@company.com"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Phone Number</label>
                  <input
                    type="tel"
                    value={quotePhone}
                    onChange={(e) => setQuotePhone(e.target.value)}
                    placeholder="+1 (555) 000-0000"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Desired Security Package</label>
                <select
                  value={quoteTier}
                  onChange={(e) => setQuoteTier(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-indigo-500"
                >
                  <option value="GOLD">Gold Tier (Full RASP + AI Fraud)</option>
                  <option value="SILVER">Silver Tier (RASP + Overlay Guard)</option>
                  <option value="BRONZE">Bronze Tier (Basic RASP)</option>
                  <option value="TRIAL">Trial Tier (30 Days)</option>
                </select>
              </div>

              <button
                type="submit"
                className="w-full bg-gradient-to-r from-emerald-500 to-indigo-600 text-white font-bold py-3.5 rounded-xl text-xs transition shadow-lg shadow-emerald-500/20"
              >
                Submit Quotation Request ➔
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
