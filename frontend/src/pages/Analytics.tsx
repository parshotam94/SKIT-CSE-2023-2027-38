import { useState, useEffect } from 'react';
import { BarChart3, TrendingUp, Shield, AlertTriangle, Download, Calendar, Settings as SettingsIcon, Eye, Bell, Ban } from 'lucide-react';
import { Link } from 'react-router-dom';
import { wafApi, AnalyticsResponse } from '../services/api';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

type AnalyticsData = AnalyticsResponse;

interface SystemConfig {
  detection_mode: string;
  demo_mode: boolean;
  demo_request_count: number;
}

const Analytics = () => {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState('24h');

  useEffect(() => {
    fetchAnalytics();
    const interval = setInterval(fetchAnalytics, 5000); // Refresh every 5s for live updates
    return () => clearInterval(interval);
  }, [timeRange]);

  const fetchAnalytics = async () => {
    try {
      setLoading(true);
      setError(null);
      const [analyticsData, configData] = await Promise.all([
        wafApi.analytics(timeRange),
        wafApi.getConfig().catch(() => null),
      ]);
      setData(analyticsData);
      setConfig(configData);
    } catch (err: any) {
      console.error('Failed to fetch analytics:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to load analytics data');
    } finally {
      setLoading(false);
    }
  };

  const exportData = (format: 'json' | 'csv') => {
    if (!data) return;

    if (format === 'json') {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `waf-analytics-${Date.now()}.json`;
      a.click();
    } else {
      const csvData = [
        ['Metric', 'Value'],
        ['Total Requests', data.total_requests],
        ['Anomalous Requests', data.total_anomalous],
        ['Detection Rate', `${data.detection_rate}%`],
        ['Avg Anomaly Score', data.avg_anomaly_score]
      ];
      const csv = csvData.map(row => row.join(',')).join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `waf-analytics-${Date.now()}.csv`;
      a.click();
    }
  };

  if (loading) {
    return (
      <div className="p-6 max-w-7xl mx-auto">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-1/4"></div>
          <div className="h-64 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-6 max-w-7xl mx-auto">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <h2 className="text-lg font-semibold text-red-800 mb-2">Error Loading Analytics</h2>
          <p className="text-red-600">{error || 'Failed to load analytics data'}</p>
          <button onClick={fetchAnalytics} className="mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Analytics</h1>
          <p className="text-gray-600 mt-2">
            Historical trends and attack pattern analysis
            {data?.data_source === 'demo' && (
              <span className="ml-2 inline-flex items-center gap-2">
                <span className="text-xs bg-yellow-100 text-yellow-800 px-2 py-1 rounded">
                  Demo Data (No Traffic Yet)
                </span>
                <Link 
                  to="/settings" 
                  className="text-xs bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700 transition-colors inline-flex items-center gap-1"
                >
                  <SettingsIcon className="w-3 h-3" />
                  Enable Demo Mode
                </Link>
              </span>
            )}
            {data?.data_source === 'real' && (
              <span className="ml-2 inline-flex items-center gap-2">
                <span className="text-xs bg-green-100 text-green-800 px-2 py-1 rounded inline-flex items-center">
                  <span className="live-pulse mr-1">●</span> Live Data
                </span>
                {config && (
                  <span className={`text-xs px-2 py-1 rounded ${
                    config.detection_mode === 'block' 
                      ? 'bg-red-100 text-red-800' 
                      : config.detection_mode === 'detect'
                      ? 'bg-yellow-100 text-yellow-800'
                      : 'bg-blue-100 text-blue-800'
                  }`}>
                    {config.detection_mode === 'block' && <><Ban className="w-3 h-3 inline mr-1" />Block</>}
                    {config.detection_mode === 'detect' && <><Bell className="w-3 h-3 inline mr-1" />Alert</>}
                    {config.detection_mode === 'monitor' && <><Eye className="w-3 h-3 inline mr-1" />Monitor</>}
                  </span>
                )}
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
          >
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
          <button
            onClick={() => exportData('json')}
            className="btn-secondary flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            JSON
          </button>
          <button
            onClick={() => exportData('csv')}
            className="btn-secondary flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            CSV
          </button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Total Requests</p>
              <p className="text-3xl font-bold text-gray-900">{data.total_requests.toLocaleString()}</p>
            </div>
            <BarChart3 className="w-10 h-10 text-blue-600" />
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Anomalous Requests</p>
              <p className="text-3xl font-bold text-orange-600">{data.total_anomalous.toLocaleString()}</p>
            </div>
            <AlertTriangle className="w-10 h-10 text-orange-600" />
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Detection Rate</p>
              <p className="text-3xl font-bold text-green-600">{data.detection_rate.toFixed(1)}%</p>
            </div>
            <Shield className="w-10 h-10 text-green-600" />
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Avg Score</p>
              <p className="text-3xl font-bold text-purple-600">{data.avg_anomaly_score.toFixed(3)}</p>
            </div>
            <TrendingUp className="w-10 h-10 text-purple-600" />
          </div>
        </div>
      </div>

      {/* Attack Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-xl font-bold text-gray-900 mb-4">Attack Type Distribution</h2>
          {Object.keys(data.attack_distribution).length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              No attacks detected yet
            </div>
          ) : (
            <div className="space-y-3">
              {(() => {
                const totalAttacks = Object.values(data.attack_distribution).reduce((sum, count) => sum + count, 0);
                return Object.entries(data.attack_distribution).map(([type, count]) => {
                  const percentage = totalAttacks > 0 ? (count / totalAttacks) * 100 : 0;
                  return (
                    <div key={type}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-gray-700">{type}</span>
                        <span className="text-sm text-gray-600">{count} ({percentage.toFixed(1)}%)</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full transition-all"
                          style={{ width: `${Math.min(percentage, 100)}%` }}
                        ></div>
                      </div>
                    </div>
                  );
                });
              })()}
            </div>
          )}
        </div>

        <div className="card">
          <h2 className="text-xl font-bold text-gray-900 mb-4">Severity Distribution</h2>
          {data.total_anomalous === 0 ? (
            <div className="text-center py-8 text-gray-500">
              No anomalous requests yet
            </div>
          ) : (
            <div className="space-y-3">
              {(() => {
                const totalSeverity = Object.values(data.severity_distribution).reduce((sum, count) => sum + count, 0);
                const colorMap: { [key: string]: string } = {
                  low: 'bg-green-500',
                  medium: 'bg-yellow-500',
                  high: 'bg-orange-500',
                  critical: 'bg-red-500'
                };
                return Object.entries(data.severity_distribution).map(([severity, count]) => {
                  const percentage = totalSeverity > 0 ? (count / totalSeverity) * 100 : 0;
                  return (
                    <div key={severity}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-gray-700 capitalize">{severity}</span>
                        <span className="text-sm text-gray-600">{count} ({percentage.toFixed(1)}%)</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div
                          className={`${colorMap[severity]} h-2 rounded-full transition-all`}
                          style={{ width: `${Math.min(percentage, 100)}%` }}
                        ></div>
                      </div>
                    </div>
                  );
                });
              })()}
            </div>
          )}
        </div>
      </div>

      {/* Hourly Trend */}
      <div className="card">
        <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
          <Calendar className="w-5 h-5" />
          Hourly Traffic Trend
        </h2>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={data.hourly_trend}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis 
              dataKey="hour" 
              tick={{ fontSize: 12 }}
              interval="preserveStartEnd"
            />
            <YAxis tick={{ fontSize: 12 }} />
            <Tooltip 
              contentStyle={{ backgroundColor: '#1f2937', border: 'none', borderRadius: '0.375rem' }}
              labelStyle={{ color: '#fff' }}
              itemStyle={{ color: '#fff' }}
            />
            <Legend />
            <Line 
              type="monotone" 
              dataKey="count" 
              stroke="#3b82f6" 
              strokeWidth={2} 
              name="Total Requests"
              dot={{ fill: '#3b82f6', r: 3 }}
              activeDot={{ r: 5 }}
            />
            <Line 
              type="monotone" 
              dataKey="anomalous" 
              stroke="#ef4444" 
              strokeWidth={2} 
              name="Anomalous"
              dot={{ fill: '#ef4444', r: 3 }}
              activeDot={{ r: 5 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default Analytics;

