'use client';

import React, { useState, useEffect } from 'react';

type UserRole = 'PUBLIC' | 'SUPER_ADMIN' | 'CLIENT';
type SubTab = 'PIPELINE' | 'PROVISION' | 'USERS' | 'LICENSE_ANALYTICS' | 'ANALYTICS_OVERVIEW' | 'ANALYTICS_CLIENTS' | 'BILLING' | 'PAYMENT_SETTINGS' | 'GLOBAL_THREATS' | 'CLIENT_OVERVIEW' | 'CLIENT_SDK' | 'CLIENT_DOCS' | 'CLIENT_THREATS' | 'CLIENT_BILLING';

export default function AppShieldEnterprisePortal() {
  const [role, setRole] = useState<UserRole>('PUBLIC');
  const [activeTab, setActiveTab] = useState<SubTab>('PIPELINE');
  const [authToken, setAuthToken] = useState<string>('');
  const [userInfo, setUserInfo] = useState<{ username: string; company_name: string; app_id: string } | null>(null);

  // Login Modal State
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [loginRole, setLoginRole] = useState<'SUPER_ADMIN' | 'CLIENT'>('SUPER_ADMIN');
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
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

  // ── New admin state ────────────────────────────────────────────────────────
  const [usersList, setUsersList] = useState<any[]>([]);
  const [licenseAnalytics, setLicenseAnalytics] = useState<any>(null);
  const [licenseSubTab, setLicenseSubTab] = useState<'expiring_soon'|'expired'|'healthy'|'long_validity'>('expiring_soon');
  const [analyticsOverview, setAnalyticsOverview] = useState<any>(null);
  const [analyticsClients, setAnalyticsClients] = useState<any[]>([]);
  const [analyticsView, setAnalyticsView] = useState<'table'|'pie'>('table');
  const [clientAnalyticsView, setClientAnalyticsView] = useState<'table'|'pie'>('table');
  // Billing admin state
  const [invoicesList, setInvoicesList] = useState<any[]>([]);
  const [clientInvoices, setClientInvoices] = useState<any[]>([]);
  const [paymentSettings, setPaymentSettings] = useState<any>(null);
  const [markPaidNote, setMarkPaidNote] = useState('');
  const [selectedInvoiceId, setSelectedInvoiceId] = useState<number|null>(null);
  const [billingMsg, setBillingMsg] = useState('');
  // Invoice creation form
  const [invClient, setInvClient] = useState('');
  const [invTier, setInvTier] = useState('GOLD');
  const [invAmount, setInvAmount] = useState('');
  const [invCurrency, setInvCurrency] = useState('INR');
  const [invDesc, setInvDesc] = useState('');
  const [invFrom, setInvFrom] = useState(new Date().toISOString().split('T')[0]);
  const [invTo, setInvTo] = useState(new Date(Date.now()+365*24*3600*1000).toISOString().split('T')[0]);
  const [invDue, setInvDue] = useState('');
  // Payment settings form
  const [psUpiId, setPsUpiId] = useState('');
  const [psUpiName, setPsUpiName] = useState('');
  const [psQr, setPsQr] = useState('');
  const [psBankName, setPsBankName] = useState('');
  const [psAccName, setPsAccName] = useState('');
  const [psAccNum, setPsAccNum] = useState('');
  const [psIfsc, setPsIfsc] = useState('');
  const [psSwift, setPsSwift] = useState('');
  const [psBranch, setPsBranch] = useState('');
  const [psInstructions, setPsInstructions] = useState('');
  const [psMsg, setPsMsg] = useState('');
  // ──────────────────────────────────────────────────────────────────────────

  // Handle Login with smooth server + demo fallback
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
      if (res.ok) {
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
        return;
      }
    // If server is unreachable, show a clear error — never expose credentials
    setLoginError('Unable to connect to the authentication server. Please try again.');
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

  // Fetch Users List
  const fetchUsers = async (token: string) => {
    try {
      const res = await fetch(`${API_BASE}/v1/admin/users`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) setUsersList(await res.json());
    } catch (e) {}
  };

  // Fetch License Analytics
  const fetchLicenseAnalytics = async (token: string) => {
    try {
      const res = await fetch(`${API_BASE}/v1/admin/licenses/analytics`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) setLicenseAnalytics(await res.json());
    } catch (e) {}
  };

  // Fetch Attack Analytics Overview
  const fetchAnalyticsOverview = async (token: string) => {
    try {
      const res = await fetch(`${API_BASE}/v1/admin/analytics/overview`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) setAnalyticsOverview(await res.json());
    } catch (e) {}
  };

  // Fetch Client-wise Analytics
  const fetchAnalyticsClients = async (token: string) => {
    try {
      const res = await fetch(`${API_BASE}/v1/admin/analytics/client-wise`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) setAnalyticsClients(await res.json());
    } catch (e) {}
  };

  // Fetch Invoices (Admin)
  const fetchInvoicesAdmin = async (token: string) => {
    try {
      const res = await fetch(`${API_BASE}/v1/admin/billing/invoices`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) setInvoicesList(await res.json());
    } catch (e) {}
  };

  // Fetch Payment Settings (Public / Client / Admin)
  const fetchPaymentSettings = async () => {
    try {
      const res = await fetch(`${API_BASE}/v1/billing/payment-settings`);
      if (res.ok) {
        const data = await res.json();
        setPaymentSettings(data);
        setPsUpiId(data.upi_id || '');
        setPsUpiName(data.upi_name || '');
        setPsQr(data.qr_code_url || '');
        setPsBankName(data.bank_name || '');
        setPsAccName(data.account_name || '');
        setPsAccNum(data.account_number || '');
        setPsIfsc(data.ifsc_code || '');
        setPsSwift(data.swift_code || '');
        setPsBranch(data.branch || '');
        setPsInstructions(data.payment_instructions || '');
      }
    } catch (e) {}
  };

  // Fetch Invoices (Client)
  const fetchClientInvoices = async (token: string) => {
    try {
      const res = await fetch(`${API_BASE}/v1/client/billing/invoices`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) setClientInvoices(await res.json());
    } catch (e) {}
  };

  // Create Invoice (Admin)
  const handleCreateInvoice = async (e: React.FormEvent) => {
    e.preventDefault();
    setBillingMsg('');
    try {
      const res = await fetch(`${API_BASE}/v1/admin/billing/invoices`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
        body: JSON.stringify({
          client_username: invClient,
          tier: invTier,
          amount: parseFloat(invAmount) || 0,
          currency: invCurrency,
          description: invDesc,
          valid_from: invFrom,
          valid_to: invTo,
          due_date: invDue
        })
      });
      const data = await res.json();
      if (res.ok) {
        setBillingMsg(`✅ Invoice ${data.invoice_number} created successfully!`);
        fetchInvoicesAdmin(authToken);
        setInvAmount('');
        setInvDesc('');
      } else {
        setBillingMsg(`❌ ${data.detail || 'Error creating invoice'}`);
      }
    } catch (e: any) {
      setBillingMsg(`❌ Error: ${e.message}`);
    }
  };

  // Mark Invoice Paid (Admin)
  const handleMarkPaid = async (invoiceId: number) => {
    try {
      const res = await fetch(`${API_BASE}/v1/admin/billing/invoices/mark-paid`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
        body: JSON.stringify({ invoice_id: invoiceId, payment_note: markPaidNote })
      });
      if (res.ok) {
        setMarkPaidNote('');
        setSelectedInvoiceId(null);
        fetchInvoicesAdmin(authToken);
      }
    } catch (e) {}
  };

  // Cancel Invoice (Admin)
  const handleCancelInvoice = async (invoiceId: number) => {
    try {
      const res = await fetch(`${API_BASE}/v1/admin/billing/invoices/cancel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
        body: JSON.stringify({ invoice_id: invoiceId })
      });
      if (res.ok) fetchInvoicesAdmin(authToken);
    } catch (e) {}
  };

  // Save Payment Settings (Admin)
  const handleSavePaymentSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setPsMsg('');
    try {
      const res = await fetch(`${API_BASE}/v1/admin/billing/payment-settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
        body: JSON.stringify({
          upi_id: psUpiId,
          upi_name: psUpiName,
          qr_code_url: psQr,
          bank_name: psBankName,
          account_name: psAccName,
          account_number: psAccNum,
          ifsc_code: psIfsc,
          swift_code: psSwift,
          branch: psBranch,
          payment_instructions: psInstructions
        })
      });
      if (res.ok) {
        setPsMsg('✅ Payment settings saved successfully!');
        fetchPaymentSettings();
      } else {
        setPsMsg('❌ Failed to save payment settings');
      }
    } catch (e: any) {
      setPsMsg(`❌ Error: ${e.message}`);
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
                  setLoginUsername('');
                  setLoginPassword('');
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
          <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-4 mb-8">
            <button onClick={() => setActiveTab('PIPELINE')}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition ${activeTab === 'PIPELINE' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>
              💼 Sales Pipeline ({leadsList.length})
            </button>
            <button onClick={() => setActiveTab('PROVISION')}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition ${activeTab === 'PROVISION' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>
              🔑 Provision Client
            </button>
            <button onClick={() => { setActiveTab('USERS'); fetchUsers(authToken); }}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition ${activeTab === 'USERS' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>
              👤 Registered Users
            </button>
            <button onClick={() => { setActiveTab('LICENSE_ANALYTICS'); fetchLicenseAnalytics(authToken); }}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition ${activeTab === 'LICENSE_ANALYTICS' ? 'bg-amber-600 text-white shadow-lg shadow-amber-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>
              📋 License Analytics
            </button>
            <button onClick={() => { setActiveTab('ANALYTICS_OVERVIEW'); fetchAnalyticsOverview(authToken); }}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition ${activeTab === 'ANALYTICS_OVERVIEW' ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>
              📊 Attack Analytics
            </button>
            <button onClick={() => { setActiveTab('ANALYTICS_CLIENTS'); fetchAnalyticsClients(authToken); }}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition ${activeTab === 'ANALYTICS_CLIENTS' ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>
              🏢 Client-wise Analytics
            </button>
            <button onClick={() => { setActiveTab('BILLING'); fetchInvoicesAdmin(authToken); fetchUsers(authToken); }}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition ${activeTab === 'BILLING' ? 'bg-violet-600 text-white shadow-lg shadow-violet-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>
              💳 Invoices & Billing
            </button>
            <button onClick={() => { setActiveTab('PAYMENT_SETTINGS'); fetchPaymentSettings(); }}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition ${activeTab === 'PAYMENT_SETTINGS' ? 'bg-teal-600 text-white shadow-lg shadow-teal-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>
              🏦 Bank & QR Setup
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

          {/* ── USERS TAB ── */}
          {activeTab === 'USERS' && (
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-bold">Registered Client Accounts</h2>
                <span className="text-xs text-slate-400 bg-slate-800 px-3 py-1.5 rounded-full">{usersList.length} clients</span>
              </div>
              {usersList.length === 0 ? (
                <p className="text-slate-500 text-center py-12">No clients registered yet.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                      <tr>{['Company','Username','Email','App ID','Tier','Valid To','Days Left','Threats','Status','Action'].map(h=><th key={h} className="py-3 px-3 whitespace-nowrap">{h}</th>)}</tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {usersList.map((u:any) => {
                        const daysLeft = u.license?.days_remaining ?? null;
                        const isExpired = u.license?.is_expired;
                        const isSoon = u.license?.is_expiring_soon;
                        return (
                          <tr key={u.username} className="hover:bg-slate-800/40 transition">
                            <td className="py-3 px-3 font-semibold text-white whitespace-nowrap">{u.company_name}</td>
                            <td className="py-3 px-3 font-mono text-indigo-300">{u.username}</td>
                            <td className="py-3 px-3 text-slate-400">{u.email}</td>
                            <td className="py-3 px-3 font-mono text-slate-400 text-[10px]">{u.app_id}</td>
                            <td className="py-3 px-3"><span className={`px-2 py-0.5 rounded-full font-bold text-[10px] ${u.license?.tier==='GOLD'?'bg-amber-500/20 text-amber-400':u.license?.tier==='SILVER'?'bg-slate-400/20 text-slate-300':u.license?.tier==='BRONZE'?'bg-orange-500/20 text-orange-400':'bg-slate-700 text-slate-400'}`}>{u.license?.tier??'NONE'}</span></td>
                            <td className="py-3 px-3 text-slate-400 whitespace-nowrap">{u.license?.valid_to??'—'}</td>
                            <td className="py-3 px-3"><span className={`font-bold ${isExpired?'text-rose-400':isSoon?'text-amber-400':'text-emerald-400'}`}>{daysLeft===null?'—':isExpired?'EXPIRED':`${daysLeft}d`}</span></td>
                            <td className="py-3 px-3 text-center font-mono text-indigo-300">{u.total_threats_detected}</td>
                            <td className="py-3 px-3"><span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${u.is_active?'bg-emerald-500/20 text-emerald-400':'bg-rose-500/20 text-rose-400'}`}>{u.is_active?'ACTIVE':'DISABLED'}</span></td>
                            <td className="py-3 px-3"><button onClick={()=>handleToggleUser(u.username)} className={`px-3 py-1 rounded-lg text-[10px] font-bold transition ${u.is_active?'bg-rose-500/20 text-rose-400 hover:bg-rose-500/40':'bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/40'}`}>{u.is_active?'Disable':'Enable'}</button></td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* ── LICENSE ANALYTICS TAB ── */}
          {activeTab === 'LICENSE_ANALYTICS' && (
            <div className="space-y-6">
              {!licenseAnalytics ? (
                <div className="text-center py-20 text-slate-500">Loading license analytics...</div>
              ) : (<>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {[{label:'Total Licenses',value:licenseAnalytics.summary.total,color:'text-indigo-400',bg:'bg-indigo-500/10 border-indigo-500/30'},{label:'🚨 Expired',value:licenseAnalytics.summary.expired,color:'text-rose-400',bg:'bg-rose-500/10 border-rose-500/30'},{label:'⚠️ Expiring ≤30d',value:licenseAnalytics.summary.expiring_soon,color:'text-amber-400',bg:'bg-amber-500/10 border-amber-500/30'},{label:'✅ Healthy',value:licenseAnalytics.summary.healthy+licenseAnalytics.summary.long_validity,color:'text-emerald-400',bg:'bg-emerald-500/10 border-emerald-500/30'}].map(c=>(
                    <div key={c.label} className={`${c.bg} border rounded-2xl p-5 text-center`}><div className={`text-3xl font-black ${c.color}`}>{c.value}</div><div className="text-xs text-slate-400 mt-1">{c.label}</div></div>
                  ))}
                </div>
                <div className="flex flex-wrap gap-2">
                  {(['expiring_soon','expired','healthy','long_validity'] as const).map(key=>{
                    const labels:{[k:string]:string}={expiring_soon:'⚠️ Expiring Soon',expired:'🚨 Expired',healthy:'✅ Healthy',long_validity:'📅 Long Validity (>180d)'};
                    return <button key={key} onClick={()=>setLicenseSubTab(key)} className={`px-4 py-2 rounded-xl text-xs font-bold transition ${licenseSubTab===key?'bg-indigo-600 text-white':'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>{labels[key]} ({(licenseAnalytics[key]??[]).length})</button>;
                  })}
                </div>
                <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 overflow-x-auto">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                      <tr>{['Company','App ID','Tier','Valid From','Valid To','Days Left','Threats'].map(h=><th key={h} className="py-3 px-4 whitespace-nowrap">{h}</th>)}</tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {(licenseAnalytics[licenseSubTab]??[]).length===0?<tr><td colSpan={7} className="py-8 text-center text-slate-500">No licenses in this category.</td></tr>:(licenseAnalytics[licenseSubTab]??[]).map((lic:any)=>(
                        <tr key={lic.license_key} className="hover:bg-slate-800/40 transition">
                          <td className="py-3 px-4 font-semibold text-white">{lic.company_name}</td>
                          <td className="py-3 px-4 font-mono text-slate-400 text-[10px]">{lic.app_id}</td>
                          <td className="py-3 px-4"><span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400">{lic.tier}</span></td>
                          <td className="py-3 px-4 text-slate-400">{lic.valid_from}</td>
                          <td className="py-3 px-4 text-slate-400">{lic.valid_to}</td>
                          <td className="py-3 px-4"><span className={`font-bold ${lic.days_remaining===0?'text-rose-400':lic.days_remaining<=30?'text-amber-400':'text-emerald-400'}`}>{lic.days_remaining===0?'EXPIRED':`${lic.days_remaining}d`}</span></td>
                          <td className="py-3 px-4 font-mono text-indigo-300">{lic.threats_detected}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>)}
            </div>
          )}

          {/* ── ATTACK ANALYTICS OVERVIEW ── */}
          {activeTab === 'ANALYTICS_OVERVIEW' && (
            <div className="space-y-6">
              {!analyticsOverview ? (
                <div className="text-center py-20 text-slate-500">Loading analytics...</div>
              ) : (<>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {[{label:'Total Detected',value:analyticsOverview.total_detected,color:'text-indigo-400',bg:'bg-indigo-500/10 border-indigo-500/30'},{label:'🛡️ Defended (≥80%)',value:analyticsOverview.defended,color:'text-emerald-400',bg:'bg-emerald-500/10 border-emerald-500/30'},{label:'⚠️ Warned (50-79%)',value:analyticsOverview.warned,color:'text-amber-400',bg:'bg-amber-500/10 border-amber-500/30'},{label:'❌ Missed (<50%)',value:analyticsOverview.missed,color:'text-rose-400',bg:'bg-rose-500/10 border-rose-500/30'}].map(c=>(
                    <div key={c.label} className={`${c.bg} border rounded-2xl p-5 text-center`}><div className={`text-3xl font-black ${c.color}`}>{c.value}</div><div className="text-xs text-slate-400 mt-1">{c.label}</div></div>
                  ))}
                </div>
                <div className="flex gap-2">
                  <button onClick={()=>setAnalyticsView('table')} className={`px-4 py-2 rounded-xl text-xs font-bold transition ${analyticsView==='table'?'bg-indigo-600 text-white':'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>📋 Table View</button>
                  <button onClick={()=>setAnalyticsView('pie')} className={`px-4 py-2 rounded-xl text-xs font-bold transition ${analyticsView==='pie'?'bg-indigo-600 text-white':'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>🥧 Pie Chart</button>
                </div>
                {analyticsView==='pie'?(
                  <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 flex flex-col md:flex-row gap-12 items-center justify-center">
                    {(()=>{
                      const tot=analyticsOverview.total_detected||1;
                      const segs=[{label:'Defended',value:analyticsOverview.defended,color:'#10b981'},{label:'Warned',value:analyticsOverview.warned,color:'#f59e0b'},{label:'Missed',value:analyticsOverview.missed,color:'#f43f5e'}];
                      let cum=0;const r=80,cx=100,cy=100;
                      return(
                        <div className="flex flex-col items-center gap-4">
                          <p className="text-xs text-slate-400 font-semibold">Defense Distribution</p>
                          <svg width="200" height="200" viewBox="0 0 200 200">
                            {segs.map((s,i)=>{const pct=s.value/tot;const sa=cum*2*Math.PI-Math.PI/2;cum+=pct;const ea=cum*2*Math.PI-Math.PI/2;const x1=cx+r*Math.cos(sa),y1=cy+r*Math.sin(sa),x2=cx+r*Math.cos(ea),y2=cy+r*Math.sin(ea);return pct>0?<path key={i} d={`M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${pct>0.5?1:0} 1 ${x2} ${y2} Z`} fill={s.color} opacity={0.85}/>:null;})}
                            <circle cx={cx} cy={cy} r={48} fill="#0f172a"/>
                            <text x={cx} y={cy-6} textAnchor="middle" fill="white" fontSize="20" fontWeight="bold">{analyticsOverview.defense_rate_pct}%</text>
                            <text x={cx} y={cy+14} textAnchor="middle" fill="#94a3b8" fontSize="9">Defense Rate</text>
                          </svg>
                          <div className="flex flex-col gap-2">{segs.map(s=><div key={s.label} className="flex items-center gap-2 text-xs"><span className="w-3 h-3 rounded-sm inline-block" style={{background:s.color}}></span><span className="text-slate-300">{s.label}: <strong>{s.value}</strong></span></div>)}</div>
                        </div>
                      );
                    })()}
                    {analyticsOverview.threat_type_breakdown.length>0&&(()=>{
                      const tot=analyticsOverview.total_detected||1;
                      const CLRS=['#6366f1','#10b981','#f59e0b','#f43f5e','#a78bfa','#34d399','#fb923c','#38bdf8'];
                      let cum=0;const r=80,cx=100,cy=100;const items=analyticsOverview.threat_type_breakdown.slice(0,8);
                      return(
                        <div className="flex flex-col items-center gap-4">
                          <p className="text-xs text-slate-400 font-semibold">Attack Type Breakdown</p>
                          <svg width="200" height="200" viewBox="0 0 200 200">
                            {items.map((item:any,i:number)=>{const pct=item.count/tot;const sa=cum*2*Math.PI-Math.PI/2;cum+=pct;const ea=cum*2*Math.PI-Math.PI/2;const x1=cx+r*Math.cos(sa),y1=cy+r*Math.sin(sa),x2=cx+r*Math.cos(ea),y2=cy+r*Math.sin(ea);return pct>0?<path key={i} d={`M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${pct>0.5?1:0} 1 ${x2} ${y2} Z`} fill={CLRS[i%CLRS.length]} opacity={0.85}/>:null;})}
                            <circle cx={cx} cy={cy} r={48} fill="#0f172a"/>
                            <text x={cx} y={cy+4} textAnchor="middle" fill="#94a3b8" fontSize="9">By Type</text>
                          </svg>
                          <div className="grid grid-cols-2 gap-1">{items.map((item:any,i:number)=><div key={item.threat} className="flex items-center gap-1.5 text-[10px]"><span className="w-2.5 h-2.5 rounded-sm inline-block" style={{background:CLRS[i%CLRS.length]}}></span><span className="text-slate-400 truncate">{item.threat}: {item.count}</span></div>)}</div>
                        </div>
                      );
                    })()}
                  </div>
                ):(
                  <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 overflow-x-auto">
                    <h3 className="text-sm font-bold text-slate-300 mb-4">Attack Type Breakdown — Full Platform</h3>
                    <table className="w-full text-left text-xs text-slate-300">
                      <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                        <tr>{['Rank','Attack Type','Detected','% Share','Frequency Bar'].map(h=><th key={h} className="py-3 px-4 whitespace-nowrap">{h}</th>)}</tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800">
                        {analyticsOverview.threat_type_breakdown.length===0?<tr><td colSpan={5} className="py-8 text-center text-slate-500">No events yet.</td></tr>:analyticsOverview.threat_type_breakdown.map((item:any,i:number)=>{
                          const pct=analyticsOverview.total_detected>0?+(item.count/analyticsOverview.total_detected*100).toFixed(1):0;
                          return(<tr key={item.threat} className="hover:bg-slate-800/40 transition">
                            <td className="py-3 px-4 text-slate-500">#{i+1}</td>
                            <td className="py-3 px-4 font-mono text-indigo-300">{item.threat}</td>
                            <td className="py-3 px-4 font-bold text-white">{item.count}</td>
                            <td className="py-3 px-4 text-slate-400">{pct}%</td>
                            <td className="py-3 px-4 w-40"><div className="bg-slate-800 rounded-full h-1.5"><div className="bg-indigo-500 h-1.5 rounded-full" style={{width:`${pct}%`}}></div></div></td>
                          </tr>);
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </>)}
            </div>
          )}

          {/* ── CLIENT-WISE ANALYTICS TAB ── */}
          {activeTab === 'ANALYTICS_CLIENTS' && (
            <div className="space-y-6">
              <div className="flex gap-2">
                <button onClick={()=>setClientAnalyticsView('table')} className={`px-4 py-2 rounded-xl text-xs font-bold transition ${clientAnalyticsView==='table'?'bg-emerald-600 text-white':'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>📋 Table View</button>
                <button onClick={()=>setClientAnalyticsView('pie')} className={`px-4 py-2 rounded-xl text-xs font-bold transition ${clientAnalyticsView==='pie'?'bg-emerald-600 text-white':'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}>🥧 Pie Chart</button>
              </div>
              {clientAnalyticsView==='pie'&&analyticsClients.length>0&&(()=>{
                const tot=analyticsClients.reduce((s:number,c:any)=>s+c.total_detected,0)||1;
                const CLRS=['#6366f1','#10b981','#f59e0b','#f43f5e','#a78bfa','#34d399','#fb923c','#38bdf8'];
                let cum=0;const r=90,cx=110,cy=110;
                return(<div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 flex flex-col md:flex-row gap-10 items-center">
                  <svg width="220" height="220" viewBox="0 0 220 220">
                    {analyticsClients.map((c:any,i:number)=>{const pct=c.total_detected/tot;const sa=cum*2*Math.PI-Math.PI/2;cum+=pct;const ea=cum*2*Math.PI-Math.PI/2;const x1=cx+r*Math.cos(sa),y1=cy+r*Math.sin(sa),x2=cx+r*Math.cos(ea),y2=cy+r*Math.sin(ea);return pct>0?<path key={i} d={`M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${pct>0.5?1:0} 1 ${x2} ${y2} Z`} fill={CLRS[i%CLRS.length]} opacity={0.85}/>:null;})}
                    <circle cx={cx} cy={cy} r={54} fill="#0f172a"/>
                    <text x={cx} y={cy+4} textAnchor="middle" fill="#94a3b8" fontSize="9">By Client</text>
                  </svg>
                  <div className="flex flex-col gap-2">
                    {analyticsClients.map((c:any,i:number)=>(
                      <div key={c.username} className="flex items-center gap-2 text-xs">
                        <span className="w-3 h-3 rounded-sm inline-block" style={{background:CLRS[i%CLRS.length]}}></span>
                        <span className="text-slate-300 font-semibold">{c.company_name}</span>
                        <span className="text-slate-500">— {c.total_detected} attacks · {c.defense_rate_pct}% defended</span>
                      </div>
                    ))}
                  </div>
                </div>);
              })()}
              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 overflow-x-auto">
                <h3 className="text-sm font-bold text-slate-300 mb-4">Client-wise Attack Defense Report</h3>
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                    <tr>{['Company','App ID','Tier','Detected','🛡️ Defended','⚠️ Warned','❌ Missed','Defense Rate','Top Threat'].map(h=><th key={h} className="py-3 px-3 whitespace-nowrap">{h}</th>)}</tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {analyticsClients.length===0?<tr><td colSpan={9} className="py-8 text-center text-slate-500">No clients with threat data yet.</td></tr>:analyticsClients.map((c:any)=>(
                      <tr key={c.username} className="hover:bg-slate-800/40 transition">
                        <td className="py-3 px-3 font-semibold text-white whitespace-nowrap">{c.company_name}</td>
                        <td className="py-3 px-3 font-mono text-slate-400 text-[10px]">{c.app_id}</td>
                        <td className="py-3 px-3"><span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400">{c.tier}</span></td>
                        <td className="py-3 px-3 font-bold text-indigo-300">{c.total_detected}</td>
                        <td className="py-3 px-3 text-emerald-400 font-bold">{c.defended}</td>
                        <td className="py-3 px-3 text-amber-400 font-bold">{c.warned}</td>
                        <td className="py-3 px-3 text-rose-400 font-bold">{c.missed}</td>
                        <td className="py-3 px-3">
                          <div className="flex items-center gap-2">
                            <div className="bg-slate-800 rounded-full h-1.5 w-20"><div className={`h-1.5 rounded-full ${c.defense_rate_pct>=80?'bg-emerald-500':c.defense_rate_pct>=50?'bg-amber-500':'bg-rose-500'}`} style={{width:`${c.defense_rate_pct}%`}}></div></div>
                            <span className={`font-bold ${c.defense_rate_pct>=80?'text-emerald-400':c.defense_rate_pct>=50?'text-amber-400':'text-rose-400'}`}>{c.defense_rate_pct}%</span>
                          </div>
                        </td>
                        <td className="py-3 px-3 font-mono text-[10px] text-indigo-300">{c.top_threat}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
          {/* ── ADMIN BILLING & INVOICES TAB ── */}
          {activeTab === 'BILLING' && (
            <div className="space-y-8">
              {/* Create Invoice Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
                <h2 className="text-2xl font-bold mb-2">Create & Issue Client Invoice</h2>
                <p className="text-slate-400 text-xs mb-6">
                  Issue manual invoice for B2B client subscription. Clients can pay via configured Bank Transfer / UPI QR code.
                </p>

                {billingMsg && (
                  <div className={`p-4 rounded-xl text-xs mb-6 font-mono ${billingMsg.startsWith('✅') ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400' : 'bg-rose-500/10 border border-rose-500/30 text-rose-400'}`}>
                    {billingMsg}
                  </div>
                )}

                <form onSubmit={handleCreateInvoice} className="space-y-4 text-xs">
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div>
                      <label className="block text-slate-400 font-semibold mb-1">Select Client</label>
                      <select
                        required
                        value={invClient}
                        onChange={(e) => setInvClient(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                      >
                        <option value="">-- Choose Client --</option>
                        {usersList.map((u: any) => (
                          <option key={u.username} value={u.username}>
                            {u.company_name} ({u.username})
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <label className="block text-slate-400 font-semibold mb-1">Package Tier</label>
                      <select
                        value={invTier}
                        onChange={(e) => setInvTier(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                      >
                        <option value="TRIAL">Trial Tier</option>
                        <option value="BRONZE">Bronze Tier</option>
                        <option value="SILVER">Silver Tier</option>
                        <option value="GOLD">Gold Tier</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-slate-400 font-semibold mb-1">Amount</label>
                      <input
                        type="number"
                        step="0.01"
                        required
                        value={invAmount}
                        onChange={(e) => setInvAmount(e.target.value)}
                        placeholder="e.g. 75000"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                      />
                    </div>

                    <div>
                      <label className="block text-slate-400 font-semibold mb-1">Currency</label>
                      <select
                        value={invCurrency}
                        onChange={(e) => setInvCurrency(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                      >
                        <option value="INR">INR (₹)</option>
                        <option value="USD">USD ($)</option>
                        <option value="EUR">EUR (€)</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                      <label className="block text-slate-400 font-semibold mb-1">Coverage Start Date</label>
                      <input
                        type="date"
                        required
                        value={invFrom}
                        onChange={(e) => setInvFrom(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                      />
                    </div>

                    <div>
                      <label className="block text-slate-400 font-semibold mb-1">Coverage Expiry Date</label>
                      <input
                        type="date"
                        required
                        value={invTo}
                        onChange={(e) => setInvTo(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                      />
                    </div>

                    <div>
                      <label className="block text-slate-400 font-semibold mb-1">Payment Due Date</label>
                      <input
                        type="date"
                        value={invDue}
                        onChange={(e) => setInvDue(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-slate-400 font-semibold mb-1">Description / Line Items</label>
                    <input
                      type="text"
                      value={invDesc}
                      onChange={(e) => setInvDesc(e.target.value)}
                      placeholder="e.g. Annual AppShield Gold Subscription for com.acmebank.mobile"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500"
                    />
                  </div>

                  <button
                    type="submit"
                    className="bg-gradient-to-r from-violet-600 to-indigo-600 hover:opacity-90 text-white font-bold py-3 px-8 rounded-xl shadow-lg shadow-violet-500/20 text-xs transition"
                  >
                    Generate &amp; Issue Invoice ➔
                  </button>
                </form>
              </div>

              {/* Invoices List Table */}
              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-xl font-bold">All Issued Invoices</h2>
                  <span className="text-xs text-slate-400 bg-slate-800 px-3 py-1 rounded-full">{invoicesList.length} total</span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                      <tr>
                        {['Invoice #', 'Company / Client', 'Tier', 'Amount', 'Valid Range', 'Due Date', 'Status', 'Actions'].map((h) => (
                          <th key={h} className="py-3 px-4 whitespace-nowrap">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {invoicesList.length === 0 ? (
                        <tr><td colSpan={8} className="py-8 text-center text-slate-500">No invoices issued yet.</td></tr>
                      ) : (
                        invoicesList.map((inv: any) => (
                          <tr key={inv.id} className="hover:bg-slate-800/40 transition">
                            <td className="py-3 px-4 font-mono font-bold text-indigo-300">{inv.invoice_number}</td>
                            <td className="py-3 px-4">
                              <span className="block font-semibold text-white">{inv.company_name}</span>
                              <span className="block text-[10px] text-slate-500 font-mono">{inv.client_username}</span>
                            </td>
                            <td className="py-3 px-4">
                              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400">{inv.tier}</span>
                            </td>
                            <td className="py-3 px-4 font-bold text-white">
                              {inv.currency === 'INR' ? '₹' : inv.currency === 'USD' ? '$' : '€'}{inv.amount.toLocaleString()}
                            </td>
                            <td className="py-3 px-4 text-slate-400 whitespace-nowrap">{inv.valid_from} → {inv.valid_to}</td>
                            <td className="py-3 px-4 text-slate-400 whitespace-nowrap">{inv.due_date || '—'}</td>
                            <td className="py-3 px-4">
                              <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold ${
                                inv.status === 'PAID' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                                inv.status === 'PENDING' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                                inv.status === 'OVERDUE' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                                'bg-slate-700 text-slate-400'
                              }`}>
                                {inv.status}
                              </span>
                            </td>
                            <td className="py-3 px-4 whitespace-nowrap">
                              {inv.status !== 'PAID' && inv.status !== 'CANCELLED' && (
                                <div className="flex gap-2">
                                  {selectedInvoiceId === inv.id ? (
                                    <div className="flex items-center gap-2">
                                      <input
                                        type="text"
                                        placeholder="UTR / Ref note..."
                                        value={markPaidNote}
                                        onChange={(e) => setMarkPaidNote(e.target.value)}
                                        className="bg-slate-950 border border-slate-700 px-2 py-1 rounded text-[10px] text-white w-28"
                                      />
                                      <button
                                        onClick={() => handleMarkPaid(inv.id)}
                                        className="bg-emerald-600 hover:bg-emerald-500 text-white text-[10px] font-bold px-2 py-1 rounded"
                                      >
                                        Confirm Paid
                                      </button>
                                      <button
                                        onClick={() => setSelectedInvoiceId(null)}
                                        className="text-slate-400 hover:text-white text-[10px]"
                                      >
                                        Cancel
                                      </button>
                                    </div>
                                  ) : (
                                    <>
                                      <button
                                        onClick={() => setSelectedInvoiceId(inv.id)}
                                        className="bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/40 px-2.5 py-1 rounded-lg text-[10px] font-bold transition"
                                      >
                                        Mark Paid
                                      </button>
                                      <button
                                        onClick={() => handleCancelInvoice(inv.id)}
                                        className="bg-rose-500/20 text-rose-400 hover:bg-rose-500/40 px-2.5 py-1 rounded-lg text-[10px] font-bold transition"
                                      >
                                        Cancel
                                      </button>
                                    </>
                                  )}
                                </div>
                              )}
                              {inv.status === 'PAID' && (
                                <span className="text-[10px] text-slate-400 font-mono">
                                  Paid: {inv.paid_at ? new Date(inv.paid_at).toLocaleDateString() : 'Yes'}
                                  {inv.payment_note && ` (${inv.payment_note})`}
                                </span>
                              )}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ── ADMIN PAYMENT SETTINGS TAB (Bank & UPI QR Configuration) ── */}
          {activeTab === 'PAYMENT_SETTINGS' && (
            <div className="space-y-8">
              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
                <h2 className="text-2xl font-bold mb-2">Manual Payment Gateway Setup (UPI &amp; Bank Details)</h2>
                <p className="text-slate-400 text-xs mb-6">
                  Configure your company UPI VPA, QR code, and Direct Bank Transfer details. Clients will see these details on their invoice pay screen.
                </p>

                {psMsg && (
                  <div className={`p-4 rounded-xl text-xs mb-6 font-mono ${psMsg.startsWith('✅') ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400' : 'bg-rose-500/10 border border-rose-500/30 text-rose-400'}`}>
                    {psMsg}
                  </div>
                )}

                <form onSubmit={handleSavePaymentSettings} className="space-y-6 text-xs">
                  {/* Section 1: UPI & QR Code */}
                  <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6">
                    <h3 className="text-sm font-bold text-teal-400 mb-4 flex items-center gap-2">
                      📱 UPI &amp; QR Code Details
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div>
                        <label className="block text-slate-400 font-semibold mb-1">UPI VPA ID</label>
                        <input
                          type="text"
                          value={psUpiId}
                          onChange={(e) => setPsUpiId(e.target.value)}
                          placeholder="e.g. appshield@icici"
                          className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-teal-500 font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-slate-400 font-semibold mb-1">UPI Payee / Merchant Name</label>
                        <input
                          type="text"
                          value={psUpiName}
                          onChange={(e) => setPsUpiName(e.target.value)}
                          placeholder="e.g. AppShield Security Technologies"
                          className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-teal-500"
                        />
                      </div>
                      <div>
                        <label className="block text-slate-400 font-semibold mb-1">QR Code Image URL / Base64</label>
                        <input
                          type="text"
                          value={psQr}
                          onChange={(e) => setPsQr(e.target.value)}
                          placeholder="https://... or data:image/png;base64,..."
                          className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-teal-500 font-mono text-[10px]"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Section 2: Bank Account Details */}
                  <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6">
                    <h3 className="text-sm font-bold text-teal-400 mb-4 flex items-center gap-2">
                      🏦 Bank Account Transfer Details (NEFT / RTGS / IMPS)
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                      <div>
                        <label className="block text-slate-400 font-semibold mb-1">Bank Name</label>
                        <input
                          type="text"
                          value={psBankName}
                          onChange={(e) => setPsBankName(e.target.value)}
                          placeholder="e.g. HDFC Bank Ltd"
                          className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-teal-500"
                        />
                      </div>
                      <div>
                        <label className="block text-slate-400 font-semibold mb-1">Account Holder Name</label>
                        <input
                          type="text"
                          value={psAccName}
                          onChange={(e) => setPsAccName(e.target.value)}
                          placeholder="e.g. AppShield Security Technologies Pvt Ltd"
                          className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-teal-500"
                        />
                      </div>
                      <div>
                        <label className="block text-slate-400 font-semibold mb-1">Account Number</label>
                        <input
                          type="text"
                          value={psAccNum}
                          onChange={(e) => setPsAccNum(e.target.value)}
                          placeholder="e.g. 50200012345678"
                          className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-teal-500 font-mono"
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div>
                        <label className="block text-slate-400 font-semibold mb-1">IFSC Code</label>
                        <input
                          type="text"
                          value={psIfsc}
                          onChange={(e) => setPsIfsc(e.target.value)}
                          placeholder="e.g. HDFC0001234"
                          className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-teal-500 font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-slate-400 font-semibold mb-1">SWIFT / BIC Code (Optional)</label>
                        <input
                          type="text"
                          value={psSwift}
                          onChange={(e) => setPsSwift(e.target.value)}
                          placeholder="e.g. HDFCINBBXXX"
                          className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-teal-500 font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-slate-400 font-semibold mb-1">Branch Name</label>
                        <input
                          type="text"
                          value={psBranch}
                          onChange={(e) => setPsBranch(e.target.value)}
                          placeholder="e.g. BKC Main Branch, Mumbai"
                          className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-teal-500"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Section 3: Payment Instructions */}
                  <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6">
                    <h3 className="text-sm font-bold text-teal-400 mb-2">📝 Instructions for Clients</h3>
                    <textarea
                      rows={3}
                      value={psInstructions}
                      onChange={(e) => setPsInstructions(e.target.value)}
                      placeholder="e.g. Please mention your Invoice # in the transfer remark. Send UTR receipt screenshot to billing@appshield.io for instant verification."
                      className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-teal-500"
                    />
                  </div>

                  <button
                    type="submit"
                    className="bg-gradient-to-r from-teal-600 to-emerald-600 hover:opacity-90 text-white font-bold py-3.5 px-8 rounded-xl shadow-lg shadow-teal-500/20 text-xs transition"
                  >
                    Save Payment Gateway Setup ➔
                  </button>
                </form>
              </div>
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
            <button
              onClick={() => { setActiveTab('CLIENT_BILLING'); fetchClientInvoices(authToken); fetchPaymentSettings(); }}
              className={`px-5 py-2.5 rounded-xl text-xs font-bold transition ${
                activeTab === 'CLIENT_BILLING' ? 'bg-violet-600 text-white shadow-lg shadow-violet-500/20' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
              }`}
            >
              💳 Invoices & Payments
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
          {/* CLIENT BILLING & PAYMENTS TAB */}
          {activeTab === 'CLIENT_BILLING' && (
            <div className="space-y-8">
              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
                <div className="flex justify-between items-center mb-6">
                  <div>
                    <h2 className="text-2xl font-bold text-white mb-1">Invoices &amp; Subscription Billing</h2>
                    <p className="text-slate-400 text-xs">
                      View issued B2B invoices and complete manual payment via Bank Transfer or UPI QR Code.
                    </p>
                  </div>
                  <span className="bg-violet-500/10 border border-violet-500/30 text-violet-400 px-4 py-1.5 rounded-full text-xs font-bold">
                    {clientInvoices.length} Issued Invoice{clientInvoices.length === 1 ? '' : 's'}
                  </span>
                </div>

                {/* Invoices List */}
                <div className="overflow-x-auto mb-8">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                      <tr>
                        {['Invoice #', 'Package Tier', 'Amount', 'Coverage Range', 'Due Date', 'Status'].map((h) => (
                          <th key={h} className="py-3 px-4 whitespace-nowrap">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {clientInvoices.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="py-8 text-center text-slate-500">
                            No billing invoices currently issued for your account.
                          </td>
                        </tr>
                      ) : (
                        clientInvoices.map((inv: any) => (
                          <tr key={inv.id} className="hover:bg-slate-800/40 transition">
                            <td className="py-3.5 px-4 font-mono font-bold text-indigo-300">{inv.invoice_number}</td>
                            <td className="py-3.5 px-4">
                              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400">
                                {inv.tier} TIER
                              </span>
                            </td>
                            <td className="py-3.5 px-4 font-bold text-white text-sm">
                              {inv.currency === 'INR' ? '₹' : inv.currency === 'USD' ? '$' : '€'}{inv.amount.toLocaleString()}
                            </td>
                            <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">{inv.valid_from} → {inv.valid_to}</td>
                            <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">{inv.due_date || '—'}</td>
                            <td className="py-3.5 px-4">
                              <span className={`px-3 py-1 rounded-full text-[10px] font-bold ${
                                inv.status === 'PAID' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                                inv.status === 'PENDING' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse' :
                                inv.status === 'OVERDUE' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                                'bg-slate-700 text-slate-400'
                              }`}>
                                {inv.status === 'PENDING' ? '⏳ PAYMENT PENDING' : inv.status === 'PAID' ? '✅ PAID & ACTIVATED' : inv.status}
                              </span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Manual Payment Methods Card */}
                <div className="bg-slate-950 border border-slate-800 rounded-2xl p-8">
                  <div className="flex items-center gap-3 mb-6 border-b border-slate-800 pb-4">
                    <div className="w-10 h-10 bg-teal-500/10 border border-teal-500/30 text-teal-400 rounded-xl flex items-center justify-center font-bold text-lg">
                      🏦
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-white">Manual Payment Details</h3>
                      <p className="text-xs text-slate-400">Transfer funds via UPI QR or Bank NEFT/RTGS to complete subscription</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    {/* Left: UPI & QR Code */}
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col items-center justify-center text-center">
                      <h4 className="text-sm font-bold text-teal-400 mb-3 uppercase tracking-wider">📱 Option 1: Instant UPI / QR Scan</h4>
                      
                      {paymentSettings?.qr_code_url ? (
                        <div className="bg-white p-3 rounded-2xl mb-4 shadow-lg border border-slate-700 max-w-[180px]">
                          <img src={paymentSettings.qr_code_url} alt="Payment QR Code" className="w-full h-auto rounded-lg" />
                        </div>
                      ) : (
                        <div className="w-36 h-36 bg-slate-950 border-2 border-dashed border-slate-800 rounded-2xl flex flex-col items-center justify-center text-slate-500 text-[10px] mb-4">
                          <span className="text-2xl mb-1">📷</span>
                          <span>Scan &amp; Pay QR</span>
                        </div>
                      )}

                      {paymentSettings?.upi_id && (
                        <div className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-left">
                          <span className="block text-[10px] text-slate-500 uppercase font-semibold">UPI VPA ID</span>
                          <div className="flex justify-between items-center">
                            <span className="font-mono text-xs text-emerald-400 font-bold">{paymentSettings.upi_id}</span>
                            <button
                              onClick={() => {
                                navigator.clipboard.writeText(paymentSettings.upi_id);
                                alert('UPI ID copied to clipboard!');
                              }}
                              className="bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] px-2.5 py-1 rounded font-bold transition"
                            >
                              Copy
                            </button>
                          </div>
                          {paymentSettings?.upi_name && (
                            <span className="block text-[10px] text-slate-400 mt-1 font-sans">Payee: {paymentSettings.upi_name}</span>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Right: Direct Bank Transfer Details */}
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-3 text-xs">
                      <h4 className="text-sm font-bold text-teal-400 mb-4 uppercase tracking-wider">🏦 Option 2: Direct Bank Transfer (NEFT / RTGS / IMPS)</h4>

                      <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 space-y-2">
                        <div className="flex justify-between">
                          <span className="text-slate-400">Bank Name:</span>
                          <span className="font-bold text-white">{paymentSettings?.bank_name || 'HDFC Bank Ltd'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Account Name:</span>
                          <span className="font-bold text-white">{paymentSettings?.account_name || 'AppShield Security Technologies'}</span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-slate-400">Account Number:</span>
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-emerald-400">{paymentSettings?.account_number || 'Contact Admin'}</span>
                            {paymentSettings?.account_number && (
                              <button
                                onClick={() => {
                                  navigator.clipboard.writeText(paymentSettings.account_number);
                                  alert('Account Number copied!');
                                }}
                                className="bg-slate-800 hover:bg-slate-700 text-slate-300 text-[9px] px-2 py-0.5 rounded font-bold"
                              >
                                Copy
                              </button>
                            )}
                          </div>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">IFSC Code:</span>
                          <span className="font-mono font-bold text-indigo-300">{paymentSettings?.ifsc_code || 'Contact Admin'}</span>
                        </div>
                        {paymentSettings?.swift_code && (
                          <div className="flex justify-between">
                            <span className="text-slate-400">SWIFT / BIC:</span>
                            <span className="font-mono font-bold text-indigo-300">{paymentSettings.swift_code}</span>
                          </div>
                        )}
                        {paymentSettings?.branch && (
                          <div className="flex justify-between">
                            <span className="text-slate-400">Branch:</span>
                            <span className="text-slate-300">{paymentSettings.branch}</span>
                          </div>
                        )}
                      </div>

                      {/* Instructions */}
                      <div className="bg-amber-500/10 border border-amber-500/30 text-amber-400 p-3 rounded-xl text-[11px] leading-relaxed">
                        <span className="font-bold block mb-1">📌 Important Payment Note:</span>
                        {paymentSettings?.payment_instructions || 'Please quote your Invoice # in the transfer remark or description. Access is provisioned upon payment confirmation.'}
                      </div>
                    </div>
                  </div>
                </div>
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
                  setLoginUsername('');
                  setLoginPassword('');
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
                  setLoginUsername('');
                  setLoginPassword('');
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
