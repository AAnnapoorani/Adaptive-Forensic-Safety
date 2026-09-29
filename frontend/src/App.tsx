import { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { DashboardPage } from './pages/DashboardPage';
import { NewInvestigationPage } from './pages/NewInvestigationPage';
import { InvestigationDetailPage } from './pages/InvestigationDetailPage';
import { EvasionLabPage } from './pages/EvasionLabPage';
import { api } from './services/api';
import { ThemeProvider } from './context/ThemeContext';

function AppContent() {
  const [currentView, setCurrentView] = useState<'dashboard' | 'new-investigation' | 'investigation-detail' | 'evasion-lab'>('dashboard');
  const [activeInvestigationId, setActiveInvestigationId] = useState<string | null>(null);
  const [systemStatus, setSystemStatus] = useState<string>('checking...');

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const checkHealth = async () => {
    try {
      const data = await api.getHealth();
      setSystemStatus(data.status || 'healthy');
    } catch {
      setSystemStatus('degraded');
    }
  };

  const handleOpenInvestigation = (id: string) => {
    setActiveInvestigationId(id);
    setCurrentView('investigation-detail');
  };

  const handleNewInvestigation = () => {
    setCurrentView('new-investigation');
  };

  const handleInvestigationStarted = (id: string) => {
    setActiveInvestigationId(id);
    setCurrentView('investigation-detail');
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar
        currentView={currentView}
        onNavigate={view => setCurrentView(view)}
        systemStatus={systemStatus}
      />

      <main style={{ flex: 1, paddingBottom: 40 }}>
        {currentView === 'dashboard' && (
          <DashboardPage
            onOpenInvestigation={handleOpenInvestigation}
            onNewInvestigation={handleNewInvestigation}
          />
        )}

        {currentView === 'new-investigation' && (
          <NewInvestigationPage
            onInvestigationStarted={handleInvestigationStarted}
            onCancel={() => setCurrentView('dashboard')}
          />
        )}

        {currentView === 'investigation-detail' && activeInvestigationId && (
          <InvestigationDetailPage
            investigationId={activeInvestigationId}
            onBack={() => setCurrentView('dashboard')}
          />
        )}

        {currentView === 'evasion-lab' && (
          <EvasionLabPage />
        )}
      </main>

      <footer style={{
        borderTop: '1px solid var(--border-subtle)',
        padding: '16px 24px',
        textAlign: 'center',
        fontSize: 12,
        color: 'var(--text-dim)',
        background: 'var(--bg-footer)',
        transition: 'background-color 0.2s ease, border-color 0.2s ease'
      }}>
        JOCKY &bull; Adaptive Intent-Driven Digital Forensics Framework &bull; Read-Only Local Evidence Collection &bull; Deterministic Provenance
      </footer>
    </div>
  );
}

export function App() {
  return (
    <ThemeProvider>
      <AppContent />
    </ThemeProvider>
  );
}

export default App;
