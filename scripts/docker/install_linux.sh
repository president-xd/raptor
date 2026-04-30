#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/../.." && pwd)

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

  fail "Cannot access the Docker daemon. Start Docker, add your user to the docker group, or run 'sudo -v' before this script."
}

dotenv_value() {
  local name=$1
  local default_value=$2
  local value="${!name:-}"
  if [ -n "$value" ]; then
    printf '%s\n' "$value"
    return
  fi
  if [ -f "$ROOT_DIR/.env" ]; then
    value=$(grep -E "^[[:space:]]*$name[[:space:]]*=" "$ROOT_DIR/.env" | tail -n 1 | cut -d= -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
    if [ -n "$value" ]; then
      printf '%s\n' "$value"
      return
    fi
  fi
  printf '%s\n' "$default_value"
}

wait_for_container_health() {
  local svc=$1
  local status=""

  echo "Waiting for $svc..."
  for _ in $(seq 1 90); do
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

  echo "Waiting for $name at $url..."
  for _ in $(seq 1 45); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "  $name ready"
      return
    fi
    sleep 2
  done

  fail "$name failed to become ready at $url"
}

stop_existing_local_apps() {
  pkill -f "uvicorn main:app.*--port $API_PORT" >/dev/null 2>&1 || true
  pkill -f "vite.*--port $FRONTEND_PORT" >/dev/null 2>&1 || true
  pkill -f "npm run dev" >/dev/null 2>&1 || true
}

echo -e "\033[1;36mRAPTOR - Full Docker Deployment\033[0m"
echo -e "\033[1;36m==========================================\033[0m"
echo ""

need_command curl

cd "$ROOT_DIR"
if [ ! -f .env ]; then
  [ -f .env.example ] || fail ".env is missing and .env.example was not found"
  cp .env.example .env
  echo "Created .env from .env.example"
fi

choose_compose_command
API_PORT=$(dotenv_value API_PORT 8000)
FRONTEND_PORT=$(dotenv_value FRONTEND_PORT 3100)

stop_existing_local_apps

echo "Starting RAPTOR (Full Docker Deployment)..."
"${COMPOSE_CMD[@]}" up -d --build

echo ""
echo "Waiting for Docker services to become ready..."
for svc in raptor-neo4j raptor-weaviate raptor-elastic raptor-redis raptor-backend; do
  wait_for_container_health "$svc"
done
wait_for_http "Frontend Dashboard" "http://localhost:$FRONTEND_PORT/"
wait_for_http "Backend API" "http://localhost:$API_PORT/api/v1/health"

echo ""
echo -e "\033[1;36m==========================================\033[0m"
echo -e "\033[0;32m  RAPTOR is now running in Docker!\033[0m"
echo ""
echo "  Dashboard:  http://localhost:$FRONTEND_PORT"
echo "  API Docs:   http://localhost:$API_PORT/docs"
echo "  Neo4j UI:   http://localhost:7474"
echo "  Weaviate:   http://localhost:8080"
echo "  Elastic:    http://localhost:9200"
echo -e "\033[1;36m==========================================\033[0m"
echo ""
