import React from 'react';
import { Shield, PlusCircle, LayoutDashboard, FlaskConical } from 'lucide-react';
import { ThemeToggle } from './ThemeToggle';

interface NavbarProps {
  currentView: string;
  onNavigate: (view: 'dashboard' | 'new-investigation' | 'evasion-lab') => void;
  systemStatus: string;
}

export const Navbar: React.FC<NavbarProps> = ({ currentView, onNavigate, systemStatus }) => {
  return (
    <header style={{
      background: 'var(--bg-nav)',
      backdropFilter: 'blur(16px)',
      WebkitBackdropFilter: 'blur(16px)',
      borderBottom: '1px solid var(--border-subtle)',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      padding: '0 24px',
      transition: 'background-color 0.2s ease, border-color 0.2s ease'
    }}>
      <div style={{
        maxWidth: 1380,
        margin: '0 auto',
        height: 64,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 16
      }}>
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, cursor: 'pointer' }} onClick={() => onNavigate('dashboard')}>
          <div style={{
            width: 38,
            height: 38,
            borderRadius: 8,
            background: 'linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 15px rgba(14, 165, 233, 0.4)'
          }}>
            <Shield size={22} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 18, fontWeight: 700, letterSpacing: '0.05em', color: 'var(--text-main)' }}>
                JOCKY
              </span>
              <span className="badge badge-in-progress" style={{ fontSize: 10 }}>v1.0.0</span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', letterSpacing: '0.02em' }}>
              Adaptive Intent-Driven Forensics Framework
            </div>
          </div>
        </div>

        {/* Navigation actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, padding: '4px 10px', background: 'var(--bg-item)', borderRadius: 20, border: '1px solid var(--border-subtle)' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: systemStatus === 'healthy' ? 'var(--accent-emerald)' : 'var(--accent-amber)', display: 'inline-block' }} />
            <span style={{ color: 'var(--text-muted)' }}>Core Status:</span>
            <span style={{ color: systemStatus === 'healthy' ? 'var(--accent-emerald)' : 'var(--accent-amber)', fontWeight: 700 }}>{systemStatus.toUpperCase()}</span>
          </div>

          <button
            className="btn btn-secondary"
            style={{ background: currentView === 'dashboard' ? 'rgba(14, 165, 233, 0.15)' : undefined, borderColor: currentView === 'dashboard' ? 'var(--accent-blue)' : undefined, color: currentView === 'dashboard' ? 'var(--accent-blue)' : undefined }}
            onClick={() => onNavigate('dashboard')}
          >
            <LayoutDashboard size={15} />
            Dashboard
          </button>

          <button
            className="btn btn-secondary"
            style={{ background: currentView === 'evasion-lab' ? 'rgba(244,63,94,0.15)' : undefined, borderColor: currentView === 'evasion-lab' ? 'var(--accent-rose)' : undefined, color: currentView === 'evasion-lab' ? 'var(--accent-rose)' : undefined }}
            onClick={() => onNavigate('evasion-lab')}
          >
            <FlaskConical size={15} />
            Evasion Lab
          </button>

          <button
            className="btn btn-primary"
            onClick={() => onNavigate('new-investigation')}
          >
            <PlusCircle size={15} />
            New Investigation
          </button>

          <ThemeToggle />
        </div>
      </div>
    </header>
  );
};
