#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
API_PORT=${API_PORT:-8000}
FRONTEND_PORT=${FRONTEND_PORT:-3100}
BACKEND_LOG="$ROOT_DIR/backend/backend.log"
FRONTEND_LOG="$ROOT_DIR/frontend/frontend.log"

fail() {
  echo ""
  echo -e "\033[0;31m[ERROR]\033[0m $*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required but was not found in PATH"
}

choose_compose_command() {
  need_command docker

  if docker info >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      COMPOSE_CMD=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
      COMPOSE_CMD=(docker-compose)
    else
      fail "Docker is available, but neither 'docker compose' nor 'docker-compose' is installed"
    fi
    DOCKER_CMD=(docker)
    return
  fi

  if command -v sudo >/dev/null 2>&1 && sudo -n docker info >/dev/null 2>&1; then
    if sudo -n docker compose version >/dev/null 2>&1; then
      COMPOSE_CMD=(sudo -n docker compose)
    elif command -v docker-compose >/dev/null 2>&1 && sudo -n docker-compose version >/dev/null 2>&1; then
      COMPOSE_CMD=(sudo -n docker-compose)
    else
      fail "Docker is available through sudo, but Compose is not installed"
    fi
    DOCKER_CMD=(sudo -n docker)
    return
  fi

  if [ -t 0 ] && command -v sudo >/dev/null 2>&1; then
    echo "Docker requires elevated access; sudo may ask for your password."
    if sudo docker info >/dev/null 2>&1; then
      if sudo docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD=(sudo docker compose)
      elif command -v docker-compose >/dev/null 2>&1 && sudo docker-compose version >/dev/null 2>&1; then
        COMPOSE_CMD=(sudo docker-compose)
      else
        fail "Docker is available through sudo, but Compose is not installed"
      fi
      DOCKER_CMD=(sudo docker)
      return
    fi
  fi

  fail "Cannot access the Docker daemon. Add your user to the docker group, start Docker, or run 'sudo -v' before this script."
}

wait_for_container_health() {
  local svc=$1
  local status=""

  echo "Waiting for $svc..."
  for _ in $(seq 1 60); do
    status=$("${DOCKER_CMD[@]}" inspect --format='{{.State.Health.Status}}' "$svc" 2>/dev/null || true)
    if [ "$status" = "healthy" ]; then
      echo "  $svc healthy"
      return
    fi
    sleep 2
  done

  fail "$svc did not become healthy. Check with: ${DOCKER_CMD[*]} logs $svc"
}

wait_for_http() {
  local name=$1
  local url=$2
  local log_path=$3

  echo "Waiting for $name at $url..."
  for _ in $(seq 1 40); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "  $name ready"
      return
    fi
    sleep 1
  done

  echo ""
  echo "$name did not become ready. Last log lines:"
  tail -n 80 "$log_path" 2>/dev/null || true
  fail "$name failed to start on $url"
}

stop_existing_apps() {
  pkill -f "uvicorn main:app" >/dev/null 2>&1 || true
  pkill -f "vite.*--port $FRONTEND_PORT" >/dev/null 2>&1 || true
  pkill -f "npm run dev" >/dev/null 2>&1 || true
}

start_detached() {
  local log_path=$1
  local workdir=$2
  shift 2

  : > "$log_path"
  if command -v setsid >/dev/null 2>&1; then
    (cd "$workdir" && setsid "$@" >> "$log_path" 2>&1 < /dev/null &)
  else
    (cd "$workdir" && nohup "$@" >> "$log_path" 2>&1 < /dev/null &)
  fi
}

echo -e "\033[0;31m  ██████   █████  ██████  ████████  ██████  ██████  \033[0m"
echo -e "\033[0;31m  ██   ██ ██   ██ ██   ██    ██    ██    ██ ██   ██ \033[0m"
echo -e "\033[0;31m  ██████  ███████ ██████     ██    ██    ██ ██████  \033[0m"
echo -e "\033[0;31m  ██   ██ ██   ██ ██         ██    ██    ██ ██   ██ \033[0m"
echo -e "\033[0;31m  ██   ██ ██   ██ ██         ██     ██████  ██   ██ \033[0m"
echo ""
echo -e "\033[1;36m==========================================\033[0m"
echo ""

need_command python3
need_command npm
need_command curl

cd "$ROOT_DIR"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

if [ "${RAPTOR_SKIP_INFRA:-false}" = "true" ]; then
  echo "[1/6] Skipping Infrastructure (RAPTOR_SKIP_INFRA=true)..."
  echo "[2/6] Skipping container health checks..."
else
  choose_compose_command

  echo "[1/6] Starting Infrastructure (Docker)..."
  "${COMPOSE_CMD[@]}" up -d neo4j weaviate elasticsearch redis

  echo "[2/6] Waiting for services to become healthy..."
  for svc in raptor-neo4j raptor-weaviate raptor-elastic raptor-redis; do
    wait_for_container_health "$svc"
  done
fi

echo "[3/6] Checking Backend Python dependencies..."
cd "$ROOT_DIR/backend"
if ! python3 -c "import fastapi, uvicorn, openai, neo4j, weaviate, elasticsearch, loguru" >/dev/null 2>&1; then
  python3 -m pip install -r requirements.txt
fi

echo "[4/6] Checking Frontend dependencies..."
cd "$ROOT_DIR/frontend"
if [ ! -d node_modules ]; then
  npm install
fi

echo "[5/6] Starting Backend API (FastAPI on :$API_PORT)..."
stop_existing_apps
start_detached "$BACKEND_LOG" "$ROOT_DIR/backend" python3 -m uvicorn main:app --host 0.0.0.0 --port "$API_PORT"
wait_for_http "Backend API" "http://localhost:$API_PORT/api/v1/health" "$BACKEND_LOG"

echo "[6/6] Starting Frontend Dashboard (Vite on :$FRONTEND_PORT)..."
start_detached "$FRONTEND_LOG" "$ROOT_DIR/frontend" npm run dev -- --host 0.0.0.0 --port "$FRONTEND_PORT"
wait_for_http "Frontend Dashboard" "http://localhost:$FRONTEND_PORT/" "$FRONTEND_LOG"

echo ""
echo -e "\033[1;36m==========================================\033[0m"
echo -e "\033[0;32m  RAPTOR is now running!\033[0m"
echo ""
echo "  Dashboard:  http://localhost:$FRONTEND_PORT"
echo "  API Docs:   http://localhost:$API_PORT/docs"
echo "  Neo4j UI:   http://localhost:7474"
echo "  Weaviate:   http://localhost:8080"
echo "  Elastic:    http://localhost:9200"
echo ""
echo "  Backend log:  $BACKEND_LOG"
echo "  Frontend log: $FRONTEND_LOG"
echo "  Mock Data:    $ROOT_DIR/data/mock/apt29_campaign.json"
echo -e "\033[1;36m==========================================\033[0m"
echo ""
