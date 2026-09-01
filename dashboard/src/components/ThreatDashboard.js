import React, { useState, useEffect } from 'react';

/**
 * AppShield SaaS Dashboard - UI Component
 */
const ThreatDashboard = () => {
    const [threats, setThreats] = useState([
        { id: 1, type: 'ROOT', device: 'Pixel 6', time: '2 mins ago' },
        { id: 2, type: 'FRIDA', device: 'Samsung S22', time: '15 mins ago' },
        { id: 3, type: 'DEBUG', device: 'Pixel 4', time: '1 hour ago' }
    ]);

    return (
        <div style={{ padding: '20px', fontFamily: 'sans-serif', backgroundColor: '#f4f7f6' }}>
            <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '2px solid #333' }}>
                <h1>🛡️ AppShield Platform</h1>
                <div style={{ fontWeight: 'bold' }}>Org: Acme Corp</div>
            </header>

            <section style={{ marginTop: '30px' }}>
                <h2>Live Threat Telemetry</h2>
                <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
                    <thead>
                        <tr style={{ backgroundColor: '#333', color: '#fff' }}>
                            <th style={{ padding: '10px' }}>Type</th>
                            <th>Device</th>
                            <th>Status</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        {threats.map(threat => (
                            <tr key={threat.id} style={{ borderBottom: '1px solid #ddd' }}>
                                <td style={{ padding: '10px', color: threat.type === 'FRIDA' ? 'red' : 'orange', fontWeight: 'bold' }}>
                                    {threat.type}
                                </td>
                                <td>{threat.device}</td>
                                <td><span style={{ backgroundColor: '#fee', color: '#c00', padding: '2px 8px', borderRadius: '4px' }}>Blocked</span></td>
                                <td>{threat.time}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </section>

            <section style={{ marginTop: '40px' }}>
                <h2>Active Apps</h2>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '20px' }}>
                    <div style={{ padding: '15px', border: '1px solid #ccc', borderRadius: '8px' }}>
                        <h3>com.acme.banking</h3>
                        <p>Status: Protected (v2.1)</p>
                        <button>Edit Policy</button>
                    </div>
                    <div style={{ padding: '15px', border: '1px solid #ccc', borderRadius: '8px' }}>
                        <h3>com.acme.crypto</h3>
                        <p>Status: Protected (v1.0)</p>
                        <button>Edit Policy</button>
                    </div>
                </div>
            </section>
            <section style={{ marginTop: '40px' }}>
                <h2>Document & AI Verification</h2>
                <div style={{ padding: '20px', border: '1px solid #ccc', borderRadius: '8px', backgroundColor: '#fff' }}>
                    <h3>Upload ID / Document for Scan</h3>
                    <p style={{ color: '#555' }}>
                        Analyze images for deepfake artifacts, digital tampering, and AI-generated synthetic identities.
                    </p>
                    <div style={{ marginTop: '15px' }}>
                        <input type="file" accept="image/*" style={{ display: 'block', marginBottom: '15px' }} />
                        <button style={{ padding: '8px 16px', backgroundColor: '#333', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                            Verify Document Authenticity
                        </button>
                    </div>
                </div>
            </section>
        </div>
    );
};

export default ThreatDashboard;
