import { useState } from 'react';
import { Shield, Lock, Database, Code, FileText, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react';

const Documentation = () => {
  const [activeSection, setActiveSection] = useState<string | null>('architecture');

  const toggleSection = (section: string) => {
    setActiveSection(activeSection === section ? null : section);
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Documentation</h1>
        <p className="text-gray-600 mt-2">Security architecture, API reference, and compliance mapping</p>
      </div>

      {/* Security Architecture */}
      <div className="card">
        <button
          onClick={() => toggleSection('architecture')}
          className="w-full flex items-center justify-between"
        >
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-blue-600" />
            <h2 className="text-xl font-bold text-gray-900">Security Architecture</h2>
          </div>
          {activeSection === 'architecture' ? <ChevronDown /> : <ChevronRight />}
        </button>
        
        {activeSection === 'architecture' && (
          <div className="mt-6 space-y-4 text-gray-700">
            <h3 className="text-lg font-semibold text-gray-900">CIA Triad Implementation</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 bg-blue-50 rounded-lg">
                <h4 className="font-semibold text-blue-900 mb-2">Confidentiality</h4>
                <ul className="text-sm space-y-1">
                  <li>• PII masking in logs</li>
                  <li>• API key authentication</li>
                  <li>• HTTPS/TLS encryption</li>
                  <li>• Sensitive data filtering</li>
                </ul>
              </div>
              <div className="p-4 bg-green-50 rounded-lg">
                <h4 className="font-semibold text-green-900 mb-2">Integrity</h4>
                <ul className="text-sm space-y-1">
                  <li>• SHA-256 request hashing</li>
                  <li>• Input validation (Pydantic)</li>
                  <li>• Tamper-evident logging</li>
                  <li>• Cryptographic verification</li>
                </ul>
              </div>
              <div className="p-4 bg-purple-50 rounded-lg">
                <h4 className="font-semibold text-purple-900 mb-2">Availability</h4>
                <ul className="text-sm space-y-1">
                  <li>• Rate limiting (DoS protection)</li>
                  <li>• Async non-blocking architecture</li>
                  <li>• Health monitoring endpoints</li>
                  <li>• Graceful error handling</li>
                </ul>
              </div>
            </div>

            <h3 className="text-lg font-semibold text-gray-900 mt-6">Defense in Depth (5 Layers)</h3>
            <ol className="list-decimal list-inside space-y-2">
              <li><strong>Network Layer:</strong> CORS, trusted host validation, TLS enforcement</li>
              <li><strong>Application Layer:</strong> Input validation, security headers, rate limiting</li>
              <li><strong>ML Detection Layer:</strong> Transformer-based anomaly detection</li>
              <li><strong>Logging Layer:</strong> Forensic logging with PII masking</li>
              <li><strong>DevSecOps Layer:</strong> Automated security scanning (SAST, DAST, SCA)</li>
            </ol>

            <h3 className="text-lg font-semibold text-gray-900 mt-6">Zero Trust Principles</h3>
            <ul className="list-disc list-inside space-y-1">
              <li>Never trust, always verify (all requests inspected)</li>
              <li>Least privilege access (API keys for sensitive ops)</li>
              <li>Assume breach (comprehensive logging for forensics)</li>
              <li>Verify explicitly (ML-based anomaly detection)</li>
            </ul>
          </div>
        )}
      </div>

      {/* Threat Modeling */}
      <div className="card">
        <button
          onClick={() => toggleSection('threats')}
          className="w-full flex items-center justify-between"
        >
          <div className="flex items-center gap-3">
            <Lock className="w-6 h-6 text-red-600" />
            <h2 className="text-xl font-bold text-gray-900">Threat Modeling (STRIDE + DREAD)</h2>
          </div>
          {activeSection === 'threats' ? <ChevronDown /> : <ChevronRight />}
        </button>
        
        {activeSection === 'threats' && (
          <div className="mt-6 space-y-4 text-gray-700">
            <h3 className="text-lg font-semibold text-gray-900">STRIDE Analysis</h3>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Threat</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Example</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Mitigation</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200 text-sm">
                  <tr>
                    <td className="px-4 py-3 font-semibold">Spoofing</td>
                    <td className="px-4 py-3">Forged API requests</td>
                    <td className="px-4 py-3">API key authentication, rate limiting</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-semibold">Tampering</td>
                    <td className="px-4 py-3">Modified request payloads</td>
                    <td className="px-4 py-3">Request hashing, input validation</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-semibold">Repudiation</td>
                    <td className="px-4 py-3">Denying malicious actions</td>
                    <td className="px-4 py-3">Append-only logs, unique incident IDs</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-semibold">Information Disclosure</td>
                    <td className="px-4 py-3">PII leakage in logs</td>
                    <td className="px-4 py-3">IP masking, sensitive data filtering</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-semibold">Denial of Service</td>
                    <td className="px-4 py-3">Request flooding</td>
                    <td className="px-4 py-3">Rate limiting, request size limits</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-semibold">Elevation of Privilege</td>
                    <td className="px-4 py-3">Unauthorized admin access</td>
                    <td className="px-4 py-3">Least privilege, API key enforcement</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <h3 className="text-lg font-semibold text-gray-900 mt-6">DREAD Risk Scores</h3>
            <p className="text-sm">High-priority threats based on quantitative risk assessment:</p>
            <ul className="list-disc list-inside space-y-1 text-sm">
              <li><strong>MITM Attack</strong> - Score: 36 (High) - Mitigated by TLS/HTTPS</li>
              <li><strong>DoS via Request Flooding</strong> - Score: 35 (High) - Mitigated by rate limiting</li>
              <li><strong>Model Poisoning</strong> - Score: 34 (High) - Hash verification needed</li>
            </ul>
          </div>
        )}
      </div>

      {/* API Reference */}
      <div className="card">
        <button
          onClick={() => toggleSection('api')}
          className="w-full flex items-center justify-between"
        >
          <div className="flex items-center gap-3">
            <Code className="w-6 h-6 text-green-600" />
            <h2 className="text-xl font-bold text-gray-900">API Reference</h2>
          </div>
          {activeSection === 'api' ? <ChevronDown /> : <ChevronRight />}
        </button>
        
        {activeSection === 'api' && (
          <div className="mt-6 space-y-4 text-gray-700">
            <div className="flex items-center gap-2 mb-4">
              <a
                href="http://localhost:8000/docs"
                target="_blank"
                rel="noopener noreferrer"
                className="btn-primary flex items-center gap-2"
              >
                <ExternalLink className="w-4 h-4" />
                Open Interactive API Docs (Swagger)
              </a>
              <a
                href="http://localhost:8000/redoc"
                target="_blank"
                rel="noopener noreferrer"
                className="btn-secondary flex items-center gap-2"
              >
                <ExternalLink className="w-4 h-4" />
                Open ReDoc
              </a>
            </div>

            <h3 className="text-lg font-semibold text-gray-900">Core Endpoints</h3>
            <div className="space-y-3">
              <div className="p-4 bg-gray-50 rounded-lg font-mono text-sm">
                <div className="flex items-center gap-2 mb-2">
                  <span className="px-2 py-1 bg-green-500 text-white rounded font-semibold">GET</span>
                  <span>/health</span>
                </div>
                <p className="text-gray-600 text-xs">System health check and uptime</p>
              </div>

              <div className="p-4 bg-gray-50 rounded-lg font-mono text-sm">
                <div className="flex items-center gap-2 mb-2">
                  <span className="px-2 py-1 bg-blue-500 text-white rounded font-semibold">POST</span>
                  <span>/scan</span>
                </div>
                <p className="text-gray-600 text-xs">Scan single HTTP request for anomalies</p>
              </div>

              <div className="p-4 bg-gray-50 rounded-lg font-mono text-sm">
                <div className="flex items-center gap-2 mb-2">
                  <span className="px-2 py-1 bg-blue-500 text-white rounded font-semibold">POST</span>
                  <span>/scan/batch</span>
                </div>
                <p className="text-gray-600 text-xs">Batch scanning (up to 100 requests)</p>
              </div>

              <div className="p-4 bg-gray-50 rounded-lg font-mono text-sm">
                <div className="flex items-center gap-2 mb-2">
                  <span className="px-2 py-1 bg-blue-500 text-white rounded font-semibold">POST</span>
                  <span>/simulate/attack</span>
                </div>
                <p className="text-gray-600 text-xs">Simulate attacks for testing (SQL, XSS, Path Traversal, Command Injection)</p>
              </div>
<div className="p-4 bg-gray-50 rounded-lg font-mono text-sm">
                <div className="flex items-center gap-2 mb-2">
                  <span className="px-2 py-1 bg-purple-500 text-white rounded font-semibold">WS</span>
                  <span>/ws/live</span>
                </div>
                <p className="text-gray-600 text-xs">WebSocket for real-time detection streaming</p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Compliance Mapping */}
      <div className="card">
        <button
          onClick={() => toggleSection('compliance')}
          className="w-full flex items-center justify-between"
        >
          <div className="flex items-center gap-3">
            <FileText className="w-6 h-6 text-purple-600" />
            <h2 className="text-xl font-bold text-gray-900">Compliance Mapping</h2>
          </div>
          {activeSection === 'compliance' ? <ChevronDown /> : <ChevronRight />}
        </button>
        
        {activeSection === 'compliance' && (
          <div className="mt-6 space-y-4 text-gray-700">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Framework</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Coverage</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200 text-sm">
                  <tr>
                    <td className="px-4 py-3 font-semibold">ISO/IEC 27001:2022</td>
                    <td className="px-4 py-3">18/18 controls (100%)</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-xs font-semibold">✓ Full</span>
                    </td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-semibold">NIST CSF v1.1</td>
                    <td className="px-4 py-3">22/23 subcategories (96%)</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-xs font-semibold">✓ High</span>
                    </td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-semibold">OWASP ASVS v4.0 L2</td>
                    <td className="px-4 py-3">32/38 requirements (84%)</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs font-semibold">✓ Good</span>
                    </td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-semibold">GDPR (Privacy by Design)</td>
                    <td className="px-4 py-3">All principles (100%)</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-xs font-semibold">✓ Full</span>
                    </td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-semibold">PCI DSS v4.0</td>
                    <td className="px-4 py-3">Foundational controls (90%)</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-xs font-semibold">✓ High</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* SSDLC Mapping */}
      <div className="card">
        <button
          onClick={() => toggleSection('ssdlc')}
          className="w-full flex items-center justify-between"
        >
          <div className="flex items-center gap-3">
            <Database className="w-6 h-6 text-orange-600" />
            <h2 className="text-xl font-bold text-gray-900">Secure SDLC (Modules I-V)</h2>
          </div>
          {activeSection === 'ssdlc' ? <ChevronDown /> : <ChevronRight />}
        </button>
        
        {activeSection === 'ssdlc' && (
          <div className="mt-6 space-y-4 text-gray-700">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-blue-50 rounded-lg">
                <h4 className="font-semibold text-blue-900 mb-2">Module I: Security Principles</h4>
                <ul className="text-sm space-y-1">
                  <li>✓ CIA Triad implementation</li>
                  <li>✓ Defense in Depth (5 layers)</li>
                  <li>✓ Least Privilege</li>
                  <li>✓ OWASP Top 10 mitigation</li>
                </ul>
              </div>

              <div className="p-4 bg-green-50 rounded-lg">
                <h4 className="font-semibold text-green-900 mb-2">Module II: Threat Modeling</h4>
                <ul className="text-sm space-y-1">
                  <li>✓ STRIDE analysis</li>
                  <li>✓ DREAD risk scoring</li>
                  <li>✓ Attack trees</li>
                  <li>✓ Data flow diagrams</li>
                </ul>
              </div>

              <div className="p-4 bg-purple-50 rounded-lg">
                <h4 className="font-semibold text-purple-900 mb-2">Module III: Secure Coding</h4>
                <ul className="text-sm space-y-1">
                  <li>✓ Input validation (Pydantic)</li>
                  <li>✓ Error handling</li>
                  <li>✓ CERT/SEI guidelines</li>
                  <li>✓ No hardcoded secrets</li>
                </ul>
              </div>

              <div className="p-4 bg-yellow-50 rounded-lg">
                <h4 className="font-semibold text-yellow-900 mb-2">Module IV: DevSecOps</h4>
                <ul className="text-sm space-y-1">
                  <li>✓ SAST (Bandit)</li>
                  <li>✓ SCA (Safety, pip-audit)</li>
                  <li>✓ DAST (OWASP ZAP)</li>
                  <li>✓ Container security (Trivy)</li>
                </ul>
              </div>

              <div className="p-4 bg-red-50 rounded-lg col-span-full">
                <h4 className="font-semibold text-red-900 mb-2">Module V: Compliance & Standards</h4>
                <ul className="text-sm space-y-1">
                  <li>✓ ISO 27001 mapping (100%)</li>
                  <li>✓ NIST CSF mapping (96%)</li>
                  <li>✓ OWASP ASVS L2 (84%)</li>
                  <li>✓ GDPR compliance (100%)</li>
                </ul>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Documentation;

