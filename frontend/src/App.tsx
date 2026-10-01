import { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { DashboardPage } from './pages/DashboardPage';
import { NewInvestigationPage } from './pages/NewInvestigationPage';
import { InvestigationDetailPage } from './pages/InvestigationDetailPage';
import { MachineDetailPage } from './pages/MachineDetailPage';
import { EvasionLabPage } from './pages/EvasionLabPage';
import { api } from './services/api';
import { ThemeProvider } from './context/ThemeContext';

function parseUrlRoute(): {
  view: 'dashboard' | 'new-investigation' | 'investigation-detail' | 'evasion-lab' | 'machine-detail';
  investigationId: string | null;
  machineId: string | null;
} {
  const path = window.location.pathname;
  if (path === '/new' || path === '/new-investigation') {
    return { view: 'new-investigation', investigationId: null, machineId: null };
  }
  if (path === '/evasion' || path === '/evasion-lab') {
    return { view: 'evasion-lab', investigationId: null, machineId: null };
  }
  const invMatch = path.match(/^\/investigations\/([^/]+)/);
  if (invMatch) {
    return { view: 'investigation-detail', investigationId: decodeURIComponent(invMatch[1]), machineId: null };
  }
  const machineMatch = path.match(/^\/machines\/([^/]+)/);
  if (machineMatch) {
    return { view: 'machine-detail', investigationId: null, machineId: decodeURIComponent(machineMatch[1]) };
  }
  return { view: 'dashboard', investigationId: null, machineId: null };
}

function AppContent() {
  const initial = parseUrlRoute();
  const [currentView, setCurrentView] = useState<'dashboard' | 'new-investigation' | 'investigation-detail' | 'evasion-lab' | 'machine-detail'>(initial.view);
  const [activeInvestigationId, setActiveInvestigationId] = useState<string | null>(initial.investigationId);
  const [selectedMachineId, setSelectedMachineId] = useState<string | null>(initial.machineId);
  const [systemStatus, setSystemStatus] = useState<string>('checking...');

  // Sync state on Browser Back/Forward navigation
  useEffect(() => {
    const handlePopState = () => {
      const route = parseUrlRoute();
      setCurrentView(route.view);
      setActiveInvestigationId(route.investigationId);
      setSelectedMachineId(route.machineId);
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const navigateTo = (
    view: 'dashboard' | 'new-investigation' | 'investigation-detail' | 'evasion-lab' | 'machine-detail',
    path: string,
    invId: string | null = null,
    machId: string | null = null
  ) => {
    setCurrentView(view);
    setActiveInvestigationId(invId);
    setSelectedMachineId(machId);
    const search = window.location.search;
    const newUrl = `${path}${search}`;
    if (window.location.pathname + window.location.search !== newUrl) {
      window.history.pushState({}, '', newUrl);
    }
  };

  const checkHealth = async () => {
    try {
      const data = await api.getHealth();
      setSystemStatus(data.status || 'healthy');
    } catch {
      setSystemStatus('degraded');
    }
  };

  const handleOpenInvestigation = (id: string) => {
    navigateTo('investigation-detail', `/investigations/${id}`, id, null);
  };

  const handleNewInvestigation = (targetMachineId?: string) => {
    navigateTo('new-investigation', '/new', null, targetMachineId || null);
  };

  const handleOpenMachine = (machineId: string) => {
    navigateTo('machine-detail', `/machines/${machineId}`, null, machineId);
  };

  const handleInvestigationStarted = (id: string) => {
    navigateTo('investigation-detail', `/investigations/${id}`, id, null);
  };

  const handleNavbarNavigate = (view: 'dashboard' | 'new-investigation' | 'evasion-lab') => {
    if (view === 'dashboard') navigateTo('dashboard', '/', null, null);
    else if (view === 'new-investigation') navigateTo('new-investigation', '/new', null, null);
    else if (view === 'evasion-lab') navigateTo('evasion-lab', '/evasion', null, null);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar
        currentView={currentView === 'machine-detail' ? 'dashboard' : currentView}
        onNavigate={handleNavbarNavigate}
        systemStatus={systemStatus}
      />

      <main style={{ flex: 1, paddingBottom: 40 }}>
        {currentView === 'dashboard' && (
          <DashboardPage
            onOpenInvestigation={handleOpenInvestigation}
            onNewInvestigation={handleNewInvestigation}
            onOpenMachine={handleOpenMachine}
          />
        )}

        {currentView === 'machine-detail' && selectedMachineId && (
          <MachineDetailPage
            machineId={selectedMachineId}
            onBack={() => navigateTo('dashboard', '/')}
            onStartInvestigation={handleNewInvestigation}
          />
        )}

        {currentView === 'new-investigation' && (
          <NewInvestigationPage
            onInvestigationStarted={handleInvestigationStarted}
            onCancel={() => navigateTo('dashboard', '/')}
          />
        )}

        {currentView === 'investigation-detail' && activeInvestigationId && (
          <InvestigationDetailPage
            investigationId={activeInvestigationId}
            onBack={() => navigateTo('dashboard', '/')}
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
        SUVADU &bull; Adaptive Intent-Driven Digital Forensics Framework &bull; Read-Only Local Evidence Collection &bull; Deterministic Provenance
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
