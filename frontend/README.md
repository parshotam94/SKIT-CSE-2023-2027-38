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
