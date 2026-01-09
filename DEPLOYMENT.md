# CloudSentinel Deployment Guide

## Quick Deploy (5 minutes)

### Step 1: Deploy Backend to Railway

1. Go to [railway.app](https://railway.app)
2. Click "New Project" → "Deploy from GitHub repo"
3. Connect your repo: `cloudsentinel`
4. Add environment variables:
   - `AWS_ACCESS_KEY_ID` (for real scans)
   - `AWS_SECRET_ACCESS_KEY` (for real scans)
5. Deploy! Get your URL like: `https://cloudsentinel-production.up.railway.app`

### Step 2: Deploy Frontend to Vercel

1. Go to [vercel.com](https://vercel.com)
2. Click "New Project" → Import `cloudsentinel/dashboard`
3. Set environment variable:
   - `VITE_API_URL` = `https://your-railway-url.up.railway.app`
4. Deploy!

---

## Docker Deployment (Alternative)

### Local Production Test
```bash
cd cloudsentinel
docker-compose up --build
# Frontend: http://localhost:3000
# Backend: http://localhost:8000
```

### Deploy to AWS/GCP
```bash
# Build and push images
docker build -t cloudsentinel-api .
docker build -t cloudsentinel-dashboard ./dashboard

# Push to registry (ECR/GCR)
docker push <registry>/cloudsentinel-api
docker push <registry>/cloudsentinel-dashboard
```

---

## Files Created

| File | Purpose |
|------|---------|
| `Dockerfile` | Backend API container |
| `dashboard/Dockerfile` | Frontend container |
| `docker-compose.yml` | Local orchestration |
| `railway.toml` | Railway config |
| `dashboard/vercel.json` | Vercel config |
| `dashboard/nginx.conf` | Production server |
| `.env.example` | Environment template |

---

## Environment Variables

### Backend (Railway)
```
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
AWS_DEFAULT_REGION=us-east-1
```

### Frontend (Vercel)
```
VITE_API_URL=https://your-api.railway.app
```
