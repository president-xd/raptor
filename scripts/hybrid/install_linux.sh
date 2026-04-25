#!/bin/bash
set -e
ROOT_DIR=$(cd "$(dirname "$0")/../.." && pwd)

echo -e "\033[0;31m  ██████   █████  ██████  ████████  ██████  ██████  \033[0m"
echo -e "\033[0;31m  ██   ██ ██   ██ ██   ██    ██    ██    ██ ██   ██ \033[0m"
echo -e "\033[0;31m  ██████  ███████ ██████     ██    ██    ██ ██████  \033[0m"
echo -e "\033[0;31m  ██   ██ ██   ██ ██         ██    ██    ██ ██   ██ \033[0m"
echo -e "\033[0;31m  ██   ██ ██   ██ ██         ██     ██████  ██   ██ \033[0m"
echo ""
echo -e "\033[1;36m==========================================\033[0m"
echo ""

echo "[1/4] Starting Infrastructure (Docker)..."
cd "$ROOT_DIR"
sudo docker-compose up -d neo4j weaviate elasticsearch redis

echo "[2/4] Waiting for services to become healthy..."
# Simple sleep for MVP since docker inspect in shell varies
echo "Waiting 20 seconds for services to initialize..."
sleep 20

echo "[3/4] Starting Backend API (FastAPI on :8000)..."
cd "$ROOT_DIR/backend"
# Kill existing uvicorn if any
pkill -f "uvicorn main:app" || true
nohup python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 > backend.log 2>&1 &

echo "[4/4] Starting Frontend Dashboard (Vite on :3100)..."
cd "$ROOT_DIR/frontend"
# Kill existing node/npm dev server if any
pkill -f "npm run dev" || true
nohup npm run dev > frontend.log 2>&1 &

echo ""
echo -e "\033[1;36m==========================================\033[0m"
echo -e "\033[0;32m  RAPTOR is now running!\033[0m"
echo ""
echo "  Dashboard:  http://localhost:3100"
echo "  API Docs:   http://localhost:8000/docs"
echo "  Neo4j UI:   http://localhost:7474"
echo "  Weaviate:   http://localhost:8080"
echo "  Elastic:    http://localhost:9200"
echo ""
echo "  Mock Data:  $ROOT_DIR/data/mock/apt29_campaign.json"
echo -e "\033[1;36m==========================================\033[0m"
echo ""
