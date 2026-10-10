import { Outlet, Link, useLocation } from 'react-router-dom';
import { Shield, Activity, BarChart3, Settings, FileText, Menu, X, Zap } from 'lucide-react';
import { useState } from 'react';

const Layout = () => {
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: Shield },
    { name: 'Live Monitoring', href: '/live', icon: Activity },
    { name: 'Attack Simulation', href: '/simulation', icon: Zap },
    { name: 'Analytics', href: '/analytics', icon: BarChart3 },
    { name: 'Settings', href: '/settings', icon: Settings },
    { name: 'Documentation', href: '/docs', icon: FileText },
  ];

  const isActive = (href: string) => location.pathname === href;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Mobile sidebar toggle */}
      <div className="lg:hidden fixed top-0 left-0 right-0 z-50 bg-white border-b border-gray-200 px-4 py-3">
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="text-gray-600 hover:text-gray-900"
        >
          {sidebarOpen ? <X size={24} /> : <Menu size={24} />}
        </button>
      </div>
       {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-64 bg-white border-r border-gray-200 transform transition-transform duration-200 ease-in-out lg:translate-x-0 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center gap-2 px-6 py-6 border-b border-gray-200">
            <Shield className="text-primary-600" size={32} />
            <div>
              <h1 className="text-xl font-bold text-gray-900">Transformer WAF</h1>
              <p className="text-xs text-gray-500">ML-Powered Security</p>
            </div>
          </div>

        {/* Navigation */}
          <nav className="flex-1 px-4 py-6 space-y-1">
            {navigation.map((item) => (
              <Link
                key={item.name}
                to={item.href}
                onClick={() => setSidebarOpen(false)}
                className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                  isActive(item.href)
                    ? 'bg-primary-50 text-primary-700'
                    : 'text-gray-700 hover:bg-gray-100'
                }`}
              ></Link> <item.icon size={20} />
                <span className="font-medium">{item.name}</span>
              </Link>
            ))}
          </nav>

          {/* Footer */}
          <div className="px-6 py-4 border-t border-gray-200">
            <div className="text-xs text-gray-500">
              <p>ISRO/DoS Academic Project</p>
              <p className="mt-1">Secure Software Development</p>
              <p className="mt-2 font-mono">v1.0.0</p>
            </div>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="lg:ml-64 min-h-screen">
        <div className="pt-16 lg:pt-0" style={{ animation: 'fadeIn 0.3s ease-out' }}>
          <Outlet />
        </div>
      </main>

      {/* Overlay for mobile */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 z-30 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  );
};

export default Layout;

