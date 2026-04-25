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

echo "Starting RAPTOR (Full Docker Deployment)..."
cd "$ROOT_DIR"
sudo docker-compose up -d

echo ""
echo -e "\033[1;36m==========================================\033[0m"
echo -e "\033[0;32m  RAPTOR is now running in Docker!\033[0m"
echo ""
echo "  Dashboard:  http://localhost:3100"
echo "  API Docs:   http://localhost:8000/docs"
echo "  Neo4j UI:   http://localhost:7474"
echo "  Weaviate:   http://localhost:8080"
echo "  Elastic:    http://localhost:9200"
echo -e "\033[1;36m==========================================\033[0m"
echo ""
