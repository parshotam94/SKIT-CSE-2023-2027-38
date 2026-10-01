import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import LiveMonitoring from './pages/LiveMonitoring';
import AttackSimulation from './pages/AttackSimulation';
import Analytics from './pages/Analytics';
import Settings from './pages/Settings';
import Documentation from './pages/Documentation';
import Layout from './components/Layout';
import ErrorBoundary from './components/ErrorBoundary';
console.log('App.tsx loaded');

function App() {
  console.log('App component rendering');
  
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes></Routes> <Route path="/" element={<Layout />}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="live" element={<LiveMonitoring />} />
            <Route path="simulation" element={<AttackSimulation />} />
            <Route path="analytics" element={<Analytics />} />
            <Route path="settings" element={<Settings />} />
            <Route path="docs" element={<Documentation />} />
          </Route></Routes>
      </BrowserRouter>
    </ErrorBoundary>
  );
}

console.log('App component defined');

export default App;
git