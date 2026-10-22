# Transformer WAF Dashboard

Production-grade React dashboard for real-time WAF monitoring and visualization.

## Features

- 🔴 **Real-time Monitoring**: Live traffic analysis and anomaly detection
- 📊 **Analytics Dashboard**: Historical trends and attack patterns  
- ⚡ **Performance Metrics**: Latency, throughput, cache hit rates
- 🛡️ **Security Visualization**: STRIDE threats, compliance mapping
- 📱 **Responsive Design**: Mobile-first Tailwind CSS

## Tech Stack

- **React 18** with TypeScript
- **Vite** for fast development
- **Tailwind CSS** for styling
- **Recharts** for data visualization
- **Axios** for API communication
- **React Router** for navigation

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Development

The dashboard connects to the WAF API at `http://127.0.0.1:8000` by default. To use a different API URL:

```bash
# Create .env file
VITE_API_URL=https://your-api-url.com
```

## Project Structure

```
frontend/
├── src/
│   ├── components/     # Reusable UI components
│   │   └── Layout.tsx
│   ├── pages/          # Page components
│   │   ├── Dashboard.tsx
│   │   ├── LiveMonitoring.tsx
│   │   ├── Analytics.tsx
│   │   ├── Settings.tsx
│   │   └── Documentation.tsx
│   ├── services/       # API clients
│   │   └── api.ts
│   ├── App.tsx         # Main app component
│   ├── main.tsx        # Entry point
│   └── index.css       # Global styles
├── public/             # Static assets
├── index.html          # HTML template
├── vite.config.ts      # Vite configuration
├── tailwind.config.js  # Tailwind configuration
└── package.json        # Dependencies
```

## Security Features

- ✅ No sensitive data in frontend code
- ✅ API token storage in localStorage (secure httpOnly cookies recommended for production)
- ✅ HTTPS enforcement for production
- ✅ Content Security Policy headers
- ✅ XSS protection via React's automatic escaping

## Production Deployment

```bash
# Build optimized bundle
npm run build

# Output in dist/ directory
# Deploy to:
# - Nginx
# - Apache
# - Vercel
# - Netlify
# - AWS S3 + CloudFront
```

## API Integration

The dashboard consumes the following WAF API endpoints:

- `GET /health` - System health check
- `POST /scan` - Scan single request
- `GET /stats` - Performance statistics
- `POST /threshold` - Update anomaly threshold

See `src/services/api.ts` for complete API client documentation.

## Academic Project Info

**Course**: Secure Software Development  
**Institution**: ISRO / Department of Space  
**Topic**: ML-based Web Application Firewall

This dashboard demonstrates:
- Secure frontend architecture
- Real-time security monitoring
- Compliance visualization
- Production-grade React practices
