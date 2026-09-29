import React from 'react';
import { Search, Activity, CheckCircle, Database, Server } from 'lucide-react';

interface StatsCardsProps {
  totalInvestigations: number;
  activeInvestigations: number;
  completedInvestigations: number;
  totalArtifacts: number;
  registeredMachines: number;
}

export const StatsCards: React.FC<StatsCardsProps> = ({
  totalInvestigations,
  activeInvestigations,
  completedInvestigations,
  totalArtifacts,
  registeredMachines
}) => {
  const cards = [
    {
      title: 'Total Investigations',
      value: totalInvestigations,
      icon: Search,
      color: 'var(--accent-blue)',
      desc: 'Overall cases logged'
    },
    {
      title: 'Active Triages',
      value: activeInvestigations,
      icon: Activity,
      color: 'var(--accent-amber)',
      desc: 'In-progress workflows'
    },
    {
      title: 'Completed Cases',
      value: completedInvestigations,
      icon: CheckCircle,
      color: 'var(--accent-emerald)',
      desc: 'Forensically verified'
    },
    {
      title: 'Evidence Artifacts',
      value: totalArtifacts,
      icon: Database,
      color: 'var(--accent-purple)',
      desc: 'Hashed & stored JSON'
    },
    {
      title: 'Registered Nodes',
      value: registeredMachines,
      icon: Server,
      color: 'var(--accent-cyan)',
      desc: 'Active forensic endpoints'
    }
  ];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginBottom: 24 }}>
      {cards.map((c, i) => {
        const Icon = c.icon;
        return (
          <div key={i} className="glass-panel" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 13, color: 'var(--text-muted)', fontWeight: 500 }}>{c.title}</span>
              <div style={{
                width: 32,
                height: 32,
                borderRadius: 8,
                background: 'var(--bg-item)',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: c.color
              }}>
                <Icon size={18} />
              </div>
            </div>
            <div>
              <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-main)', lineHeight: 1 }}>{c.value}</div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 6 }}>{c.desc}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
};
