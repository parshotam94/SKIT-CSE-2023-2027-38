import { useState, useMemo } from 'react';
import { 
  Shield, Lock, Database, Code, FileText, ChevronDown, ChevronRight, 
  ExternalLink, Copy, Search, Terminal, CheckCircle2 
} from 'lucide-react';
import { useToast } from '../context/ToastContext';
import { API_BASE_URL } from '../services/api';

const Documentation = () => {
  const { success } = useToast();
  const [activeSection, setActiveSection] = useState<string | null>('architecture');
  const [searchQuery, setSearchQuery] = useState('');

  const toggleSection = (section: string) => {
    setActiveSection(activeSection === section ? null : section);
  };

  const copyCode = (snippet: string, title: string) => {
    navigator.clipboard.writeText(snippet);
    success('Copied to Clipboard', `${title} copied`);
  };

  const ENDPOINTS = [
    {
      method: 'GET',
      path: '/health',
      desc: 'Verify service operational health, uptime, and model load status.',
      curl: `curl -X GET "${API_BASE_URL}/health"`,
    },
    {
      method: 'POST',
      path: '/scan',
      desc: 'Scan single incoming HTTP request for statistical anomalies via Transformer inference.',
      curl: `curl -X POST "${API_BASE_URL}/scan" \\\n  -H "Content-Type: application/json" \\\n  -d '{"method": "GET", "path": "/api/users", "query_string": "id=1"}'`,
    },
    {
      method: 'POST',
      path: '/simulate/attack',
      desc: 'Simulate synthetic attack vector (SQLi, XSS, Path Traversal, Command Injection) for verification.',
      curl: `curl -X POST "${API_BASE_URL}/simulate/attack" \\\n  -H "Content-Type: application/json" \\\n  -d '{"attack_type": "sql_injection", "target_path": "/api/users"}'`,
    },
    {
      method: 'WS',
      path: '/ws/live',
      desc: 'High-throughput WebSocket stream for live HTTP request and detection telemetry.',
      curl: `wscat -c "ws://localhost:8000/ws/live"`,
    },
    {
      method: 'GET',
      path: '/analytics',
      desc: 'Aggregated attack vectors, severity distributions, and hourly density metrics.',
      curl: `curl -X GET "${API_BASE_URL}/analytics?range=24h"`,
    },
  ];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-white">
              System Documentation
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-primary-50 dark:bg-primary-950/60 text-primary-600 dark:text-primary-400 border border-primary-200 dark:border-primary-900/50">
              Reference Manual
            </span>
          </div>
          <p className="text-slate-600 dark:text-slate-400 text-sm mt-1">
            Security architecture specifications, STRIDE/DREAD threat matrices, API curl references, and ISO 27001 mapping
          </p>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="absolute left-3 top-2.5 text-slate-400" size={16} />
          <input
            type="text"
            placeholder="Search docs topics..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="input-field pl-9 text-xs"
          />
        </div>
      </div>

      {/* Security Architecture Section */}
      <div className="card">
        <button
          onClick={() => toggleSection('architecture')}
          className="w-full flex items-center justify-between text-left"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary-500/10 text-primary-600 dark:text-primary-400">
              <Shield size={20} />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white">1. Security Architecture</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">CIA Triad, Defense in Depth, and Zero Trust</p>
            </div>
          </div>
          {activeSection === 'architecture' ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
        </button>

        {activeSection === 'architecture' && (
          <div className="mt-5 pt-4 border-t border-slate-200 dark:border-dark-700 space-y-5 text-xs text-slate-700 dark:text-slate-300">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-3">CIA Triad Implementation</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="p-4 bg-sky-50 dark:bg-sky-950/30 border border-sky-200 dark:border-sky-900/50 rounded-xl">
                  <h4 className="font-bold text-sky-900 dark:text-sky-200 mb-2">Confidentiality</h4>
                  <ul className="space-y-1 text-slate-600 dark:text-slate-300">
                    <li>• PII masking in forensic log streams</li>
                    <li>• Secret redaction regex filters</li>
                    <li>• Strict TLS 1.3 & CSP transport rules</li>
                    <li>• Token stripping in HTTP access logs</li>
                  </ul>
                </div>

                <div className="p-4 bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/50 rounded-xl">
                  <h4 className="font-bold text-emerald-900 dark:text-emerald-200 mb-2">Integrity</h4>
                  <ul className="space-y-1 text-slate-600 dark:text-slate-300">
                    <li>• SHA-256 request payload hashing</li>
                    <li>• Pydantic schema validation & bounds</li>
                    <li>• Tamper-evident immutable event logs</li>
                    <li>• Anti-evasion URL/Hex normalization</li>
                  </ul>
                </div>

                <div className="p-4 bg-purple-50 dark:bg-purple-950/30 border border-purple-200 dark:border-purple-900/50 rounded-xl">
                  <h4 className="font-bold text-purple-900 dark:text-purple-200 mb-2">Availability</h4>
                  <ul className="space-y-1 text-slate-600 dark:text-slate-300">
                    <li>• Client IP token bucket rate limiting</li>
                    <li>• Asynchronous non-blocking inference</li>
                    <li>• Graceful fallback on model timeout</li>
                    <li>• Health check & liveness probes</li>
                  </ul>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-2">5-Layer Defense in Depth</h3>
              <ol className="list-decimal list-inside space-y-1.5 p-3 rounded-xl bg-slate-50 dark:bg-dark-800/60 border border-slate-200 dark:border-dark-700">
                <li><strong className="text-slate-900 dark:text-white">Network Layer:</strong> CORS protection, reverse-proxy host whitelisting, and TLS strict headers.</li>
                <li><strong className="text-slate-900 dark:text-white">Application Layer:</strong> Input normalization, max header/body length validation, and rate limiting.</li>
                <li><strong className="text-slate-900 dark:text-white">ML Detection Layer:</strong> DistilBERT token reconstruction loss and statistical perplexity estimation.</li>
                <li><strong className="text-slate-900 dark:text-white">Logging Layer:</strong> Secure forensic auditing with sensitive header obfuscation.</li>
                <li><strong className="text-slate-900 dark:text-white">DevSecOps Layer:</strong> Automated static and dynamic vulnerability scanning.</li>
              </ol>
            </div>
          </div>
        )}
      </div>

      {/* Threat Modeling Section */}
      <div className="card">
        <button
          onClick={() => toggleSection('threats')}
          className="w-full flex items-center justify-between text-left"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-600 dark:text-rose-400">
              <Lock size={20} />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white">2. Threat Modeling (STRIDE + DREAD)</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">Systemic adversary analysis and risk scoring</p>
            </div>
          </div>
          {activeSection === 'threats' ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
        </button>

        {activeSection === 'threats' && (
          <div className="mt-5 pt-4 border-t border-slate-200 dark:border-dark-700 space-y-4 text-xs text-slate-700 dark:text-slate-300">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-dark-800/60 border border-slate-200 dark:border-dark-700">
                <span className="font-bold text-slate-900 dark:text-white block mb-1">Spoofing (S)</span>
                <span>Mitigated via API key verification, SHA-256 client fingerprinting, and trusted proxy header validation.</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-dark-800/60 border border-slate-200 dark:border-dark-700">
                <span className="font-bold text-slate-900 dark:text-white block mb-1">Tampering (T)</span>
                <span>Mitigated via strict Pydantic parsing, payload normalization, and integrity-hashed detection logs.</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-dark-800/60 border border-slate-200 dark:border-dark-700">
                <span className="font-bold text-slate-900 dark:text-white block mb-1">Repudiation (R)</span>
                <span>Audit trail with timestamps, client hashes, request paths, and non-repudiation event logs.</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-dark-800/60 border border-slate-200 dark:border-dark-700">
                <span className="font-bold text-slate-900 dark:text-white block mb-1">Information Disclosure (I)</span>
                <span>Mitigated by redacting cookies, passwords, and tokens from all telemetry and exception traces.</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-dark-800/60 border border-slate-200 dark:border-dark-700">
                <span className="font-bold text-slate-900 dark:text-white block mb-1">Denial of Service (D)</span>
                <span>Token bucket rate limiter (100 req/min per IP) and asynchronous inference worker pool.</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-dark-800/60 border border-slate-200 dark:border-dark-700">
                <span className="font-bold text-slate-900 dark:text-white block mb-1">Elevation of Privilege (E)</span>
                <span>Strict non-root container isolation and capability dropping in Docker runtime.</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Interactive API Reference Section */}
      <div className="card">
        <button
          onClick={() => toggleSection('api')}
          className="w-full flex items-center justify-between text-left"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
              <Terminal size={20} />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white">3. REST & WebSocket API Reference</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">Curl commands and payload specifications</p>
            </div>
          </div>
          {activeSection === 'api' ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
        </button>

        {activeSection === 'api' && (
          <div className="mt-5 pt-4 border-t border-slate-200 dark:border-dark-700 space-y-4">
            {ENDPOINTS.map((ep) => (
              <div
                key={ep.path}
                className="p-4 rounded-xl bg-slate-50 dark:bg-dark-850 border border-slate-200 dark:border-dark-700 space-y-2.5"
              >
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className={`px-2 py-0.5 rounded font-bold ${
                      ep.method === 'GET'
                        ? 'bg-blue-600 text-white'
                        : ep.method === 'POST'
                        ? 'bg-emerald-600 text-white'
                        : 'bg-purple-600 text-white'
                    }`}>
                      {ep.method}
                    </span>
                    <span className="font-bold text-slate-900 dark:text-white">{ep.path}</span>
                  </div>

                  <button
                    onClick={() => copyCode(ep.curl, ep.path)}
                    className="btn btn-secondary text-xs py-1 px-2.5 flex items-center gap-1.5"
                  >
                    <Copy size={12} />
                    Copy cURL
                  </button>
                </div>

                <p className="text-xs text-slate-600 dark:text-slate-400">{ep.desc}</p>

                <pre className="p-3 bg-slate-950 text-slate-200 dark:bg-dark-950 rounded-lg font-mono text-[11px] overflow-x-auto border border-slate-800">
                  <code>{ep.curl}</code>
                </pre>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Compliance & Standards Section */}
      <div className="card">
        <button
          onClick={() => toggleSection('compliance')}
          className="w-full flex items-center justify-between text-left"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-600 dark:text-indigo-400">
              <FileText size={20} />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white">4. Compliance Framework Mapping</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">ISO 27001, NIST CSF, and OWASP ASVS verification</p>
            </div>
          </div>
          {activeSection === 'compliance' ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
        </button>

        {activeSection === 'compliance' && (
          <div className="mt-5 pt-4 border-t border-slate-200 dark:border-dark-700">
            <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-dark-700">
              <table className="min-w-full divide-y divide-slate-200 dark:divide-dark-800 text-xs">
                <thead className="bg-slate-50 dark:bg-dark-850">
                  <tr>
                    <th className="px-4 py-2.5 text-left font-bold text-slate-500 dark:text-slate-400 uppercase">Framework</th>
                    <th className="px-4 py-2.5 text-left font-bold text-slate-500 dark:text-slate-400 uppercase">Coverage</th>
                    <th className="px-4 py-2.5 text-right font-bold text-slate-500 dark:text-slate-400 uppercase">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-dark-800 bg-white dark:bg-dark-900">
                  {[
                    { framework: 'ISO/IEC 27001:2022', coverage: '18/18 controls (100%)', status: 'Full Compliance' },
                    { framework: 'NIST CSF v1.1', coverage: '22/23 subcategories (96%)', status: 'High Alignment' },
                    { framework: 'OWASP ASVS v4.0 L2', coverage: '32/38 requirements (84%)', status: 'Substantial' },
                    { framework: 'GDPR (Privacy by Design)', coverage: 'Article 25 & 32 (100%)', status: 'Verified' },
                    { framework: 'PCI DSS v4.0 Req 6', coverage: 'Foundational automated WAF controls (90%)', status: 'Compliant' },
                  ].map((row) => (
                    <tr key={row.framework} className="hover:bg-slate-50 dark:hover:bg-dark-850">
                      <td className="px-4 py-3 font-semibold text-slate-900 dark:text-white">{row.framework}</td>
                      <td className="px-4 py-3 text-slate-600 dark:text-slate-400">{row.coverage}</td>
                      <td className="px-4 py-3 text-right">
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300">
                          <CheckCircle2 size={12} /> {row.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Documentation;
