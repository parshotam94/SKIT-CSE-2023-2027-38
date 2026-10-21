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