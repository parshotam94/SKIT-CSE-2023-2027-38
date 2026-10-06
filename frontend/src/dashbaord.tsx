import { useEffect, useState } from 'react';
import { wafApi, HealthResponse, StatsResponse, MetricsResponse, TimeseriesResponse } from '../services/api';
import { Shield, AlertTriangle, CheckCircle, Activity, Clock, Zap, Settings } from 'lucide-react';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Link } from 'react-router-dom';

interface SystemConfig {
  detection_mode: string;
  demo_mode: boolean;
  demo_request_count: number;
  demo_total_requests: number;
  anomaly_threshold: number;
}