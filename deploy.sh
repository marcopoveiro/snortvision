#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
#  SnortVision v0.1 — Super Deploy
#  Goal: reproducible first-install style deployment
#  Run: chmod +x deploy.sh && ./deploy.sh
#
#  Defaults:
#    CLEAN_INSTALL=1  -> remove previous SnortVision containers/volumes first
#    BUILD_NO_CACHE=1 -> rebuild images with no cache on clean install
#
#  Override examples:
#    CLEAN_INSTALL=0 ./deploy.sh
#    BUILD_NO_CACHE=0 ./deploy.sh
# ════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()  { echo -e "${RED}[ERR]${NC}   $*"; exit 1; }

trap 'die "Deployment failed near line $LINENO"' ERR

need_file() {
  local f="$1"
  [ -f "$f" ] || die "Required file not found: $f"
}

need_dir() {
  local d="$1"
  [ -d "$d" ] || die "Required directory not found: $d"
}

# ── Sudo / Docker helpers ───────────────────────────────────────────────────
SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
fi

DOCKER=(docker)
if ! docker info >/dev/null 2>&1; then
  if [ -n "$SUDO" ] && $SUDO docker info >/dev/null 2>&1; then
    DOCKER=($SUDO docker)
  fi
fi

run_docker() {
  "${DOCKER[@]}" "$@"
}

pick_compose() {
  if run_docker compose version >/dev/null 2>&1; then
    COMPOSE=("${DOCKER[@]}" compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    if [ -n "$SUDO" ] && $SUDO docker-compose version >/dev/null 2>&1; then
      COMPOSE=($SUDO docker-compose)
    else
      COMPOSE=(docker-compose)
    fi
  else
    return 1
  fi
}

run_compose() {
  "${COMPOSE[@]}" "$@"
}

npm_install_backend() {
  local npm_cmd=(npm)
  local npm_env=(
    "NPM_CONFIG_UPDATE_NOTIFIER=false"
    "NPM_CONFIG_FUND=false"
    "NPM_CONFIG_AUDIT=false"
    "npm_config_loglevel=notice"
  )

  if [ -d backend/node_modules ]      && (cd backend && node -e "require('express'); require('ssh2'); require('better-sqlite3'); require('dotenv'); console.log('backend deps ok')" >/dev/null 2>&1); then
    ok "Backend dependencies already usable — skipping reinstall"
    return 0
  fi

  info "Installing backend dependencies (this can take longer the first time because better-sqlite3 may compile)"
  if [ -f backend/package-lock.json ]; then
    (cd backend && env "${npm_env[@]}" "${npm_cmd[@]}" ci --omit=dev --no-audit --no-fund --foreground-scripts)
  else
    (cd backend && env "${npm_env[@]}" "${npm_cmd[@]}" install --omit=dev --no-audit --no-fund --foreground-scripts)
  fi

  (cd backend && node -e "require('express'); require('ssh2'); require('better-sqlite3'); require('dotenv'); console.log('backend deps ok')" >/dev/null)
  ok "Backend dependencies installed"
}

print_local_backend_hints() {
  echo ""
  warn "Local backend dependency build failed. The usual cause is missing native-build tools for better-sqlite3."
  echo ""
  echo "Install these first on Debian/Ubuntu, then run ./deploy.sh again:"
  echo "  sudo apt update"
  echo "  sudo apt install -y build-essential python3 make g++ pkg-config"
  echo ""
}

npm_install_frontend() {
  local npm_cmd=(npm)
  local npm_env=(
    "NPM_CONFIG_UPDATE_NOTIFIER=false"
    "NPM_CONFIG_FUND=false"
    "NPM_CONFIG_AUDIT=false"
    "npm_config_loglevel=notice"
  )

  if [ -d frontend/node_modules ] && (cd frontend && node -e "require('react'); require('react-dom'); require('vite'); console.log('frontend deps ok')" >/dev/null 2>&1); then
    ok "Frontend dependencies already usable — skipping reinstall"
    return 0
  fi

  info "Installing frontend dependencies"
  if [ -f frontend/package-lock.json ]; then
    (cd frontend && env "${npm_env[@]}" "${npm_cmd[@]}" ci --no-audit --no-fund)
  else
    (cd frontend && env "${npm_env[@]}" "${npm_cmd[@]}" install --no-audit --no-fund)
  fi

  (cd frontend && node -e "require('react'); require('react-dom'); require('vite'); console.log('frontend deps ok')" >/dev/null)
  ok "Frontend dependencies installed"
}

build_frontend_local() {
  local host_ip="$1"
  info "Building frontend for local mode"
  rm -rf frontend/dist
  (cd frontend && VITE_BACKEND_URL="http://${host_ip}:${BACKEND_PORT}" VITE_BACKEND_PORT="${BACKEND_PORT}" npm run build)
  [ -f frontend/dist/index.html ] || die "Frontend build did not produce frontend/dist/index.html"
  ok "Frontend build complete"
}

write_local_helper_scripts() {
  cat > start-local.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$(pwd)/backend"
exec node server.js
EOF
  chmod +x start-local.sh
}

# ── Env helpers ─────────────────────────────────────────────────────────────
generate_api_key() {
  if command -v openssl >/dev/null 2>&1; then
    printf 'sk-%s' "$(openssl rand -hex 24)"
  else
    printf 'sk-%s' "$(dd if=/dev/urandom bs=24 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')"
  fi
}

set_env_value() {
  local key="$1"
  local value="$2"
  local file=".env"
  local escaped
  escaped=$(printf '%s' "$value" | sed 's/[&/\\]/\\&/g')
  if grep -qE "^${key}=" "$file"; then
    sed -i "s/^${key}=.*/${key}=${escaped}/" "$file"
  else
    printf '\n%s=%s\n' "$key" "$value" >> "$file"
  fi
}

get_env_value() {
  local key="$1"
  grep -E "^${key}=" .env 2>/dev/null | head -1 | cut -d= -f2-
}

# ── Sanity checks ───────────────────────────────────────────────────────────
need_file .env.example
need_file docker-compose.yml
need_file backend/server.js
need_file frontend/package.json
need_file backend/package.json
need_dir backend
need_dir frontend

mkdir -p backend/data keys

if [ ! -f .env ]; then
  cp .env.example .env
  warn ".env created from .env.example"
else
  ok ".env found"
fi

if ! grep -qE '^API_KEY=sk-' .env; then
  API_KEY_VAL="$(generate_api_key)"
  set_env_value API_KEY "$API_KEY_VAL"
  warn "API_KEY was blank — generated a stable key in .env"
else
  API_KEY_VAL="$(get_env_value API_KEY)"
  ok "Stable API_KEY already present in .env"
fi

# Ensure these exist so backend/UI updates have a stable target
FRONTEND_PORT="$(get_env_value FRONTEND_PORT)"; FRONTEND_PORT="${FRONTEND_PORT:-3000}"
BACKEND_PORT="$(get_env_value BACKEND_PORT)"; BACKEND_PORT="${BACKEND_PORT:-4000}"
set_env_value FRONTEND_PORT "$FRONTEND_PORT"
set_env_value BACKEND_PORT "$BACKEND_PORT"

cp .env backend/.env
ok "backend/.env synced from root .env"
cat > frontend/.env.local <<EOF
VITE_BACKEND_PORT=${BACKEND_PORT}
EOF
ok "frontend/.env.local written"

SENSOR_INTERFACE_VAL="$(get_env_value SENSOR_INTERFACE)"
if [ -z "$SENSOR_INTERFACE_VAL" ]; then
  warn "SENSOR_INTERFACE is blank in .env — dashboard packet counters will stay in alert-rate mode until you set the sniffing NIC"
else
  ok "SENSOR_INTERFACE set to ${SENSOR_INTERFACE_VAL}"
fi

# Snort local directories are harmless on remote-sensor installs and useful on local ones
info "Ensuring Snort directories exist on this host"
$SUDO mkdir -p /etc/snort/rules /var/log/snort 2>/dev/null || mkdir -p /etc/snort/rules /var/log/snort || true
$SUDO touch /var/log/snort/alert_json.txt 2>/dev/null || touch /var/log/snort/alert_json.txt || true
$SUDO chmod 666 /var/log/snort/alert_json.txt 2>/dev/null || true
ok "Snort local directories ready"

CLEAN_INSTALL="${CLEAN_INSTALL:-1}"
BUILD_NO_CACHE="${BUILD_NO_CACHE:-$CLEAN_INSTALL}"

echo ""
echo -e "${BOLD}${CYAN}  🛡️  SnortVision v0.1 — Super Deploy${NC}"
echo "  ═══════════════════════════════════════"
echo ""
echo -e "  ${BOLD}Deployment mode:${NC}"
echo "    1) Docker  — frontend + backend containers"
echo "    2) Local   — backend directly on this host"
echo ""
read -rp "  Choose [1/2] (default 1): " MODE
MODE="${MODE:-1}"

# ── Local mode ──────────────────────────────────────────────────────────────
if [ "$MODE" = "2" ]; then
  info "Local mode selected"

  command -v node >/dev/null 2>&1 || die "Node.js is not installed"
  command -v npm >/dev/null 2>&1 || die "npm is not installed"
  ok "Node.js: $(node --version)"
  ok "npm: $(npm --version)"

  if ! npm_install_backend; then
    print_local_backend_hints
    die "Backend dependency installation failed in local mode"
  fi

  if ! npm_install_frontend; then
    die "Frontend dependency installation failed in local mode"
  fi

  info "Validating backend syntax"
  (cd backend && node --check server.js)
  ok "Backend syntax check passed"

  MY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  MY_IP="${MY_IP:-localhost}"

  build_frontend_local "$MY_IP"
  write_local_helper_scripts

  echo ""
  echo -e "${GREEN}${BOLD}  ✅ Local deploy prepared${NC}"
  echo ""
  echo -e "  Frontend UI        → ${CYAN}http://${MY_IP}:${BACKEND_PORT}/${NC}"
  echo -e "  Public health      → ${CYAN}http://${MY_IP}:${BACKEND_PORT}/api/public/health${NC}"
  echo -e "  Protected health   → ${CYAN}http://${MY_IP}:${BACKEND_PORT}/api/health?key=${API_KEY_VAL}${NC}"
  echo -e "  API key            → ${YELLOW}${API_KEY_VAL}${NC}"
  echo ""
  echo -e "  Start full local app with: ${CYAN}./start-local.sh${NC}"
  echo -e "  Or manually: ${CYAN}cd backend && node server.js${NC}"
  exit 0
fi

# ── Docker mode ─────────────────────────────────────────────────────────────
info "Docker mode selected"
command -v docker >/dev/null 2>&1 || die "Docker is not installed"
ok "Docker available"
pick_compose || die "Docker Compose is not available"
ok "Compose available"

info "Validating backend syntax before build"
(node --check backend/server.js >/dev/null)
ok "backend/server.js syntax ok"

if [ "$CLEAN_INSTALL" = "1" ]; then
  warn "Clean-install mode is ON — old SnortVision containers and volumes will be removed"
  run_compose down -v --remove-orphans || true
  run_docker rm -f snortvision-backend snortvision-frontend 2>/dev/null || true
else
  info "Clean-install mode is OFF — deploy will reuse existing persistent state"
fi

if [ ! -f keys/snort_id_rsa ]; then
  warn "keys/snort_id_rsa not found — SSH-key sensor mode will not work until you add it"
else
  chmod 600 keys/snort_id_rsa || true
  ok "Sensor SSH key permissions look good"
fi

if [ -f keys/router_id_rsa ]; then
  chmod 600 keys/router_id_rsa || true
  ok "Main router SSH key permissions look good"
fi

info "Building images"
if [ "$BUILD_NO_CACHE" = "1" ]; then
  run_compose build --no-cache
else
  run_compose build
fi

info "Starting containers"
run_compose up -d --force-recreate --remove-orphans

MY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
MY_IP="${MY_IP:-localhost}"
PUBLIC_HEALTH="http://127.0.0.1:${BACKEND_PORT}/api/public/health"
PROTECTED_HEALTH="http://127.0.0.1:${BACKEND_PORT}/api/health?key=${API_KEY_VAL}"

info "Waiting for backend public health"
for i in $(seq 1 45); do
  if curl -fsS "$PUBLIC_HEALTH" >/dev/null 2>&1; then
    ok "Public health endpoint is up"
    break
  fi
  sleep 2
  if [ "$i" -eq 45 ]; then
    run_compose logs --tail 80 backend || true
    die "Backend did not become healthy on /api/public/health"
  fi
done

info "Checking protected health with project API key"
if curl -fsS "$PROTECTED_HEALTH" >/dev/null 2>&1; then
  ok "Protected health endpoint accepted the API key"
else
  warn "Protected health did not answer successfully with the current API key"
fi

echo ""
echo -e "${GREEN}${BOLD}  ✅ SnortVision Docker deploy complete${NC}"
echo ""
echo -e "  Frontend           → ${CYAN}http://${MY_IP}:${FRONTEND_PORT}${NC}"
echo -e "  Backend root       → ${CYAN}http://${MY_IP}:${BACKEND_PORT}/${NC}"
echo -e "  Public health      → ${CYAN}http://${MY_IP}:${BACKEND_PORT}/api/public/health${NC}"
echo -e "  Protected health   → ${CYAN}http://${MY_IP}:${BACKEND_PORT}/api/health?key=${API_KEY_VAL}${NC}"
echo -e "  API key            → ${YELLOW}${API_KEY_VAL}${NC}"
echo ""
echo "  Notes:"
echo "    - Direct browser visits to /api/health without ?key=... will return Unauthorized."
echo "    - The frontend passes X-API-Key automatically after you save the API key in the UI."
echo "    - Main router status is optional context; Snort alerts still come from the Snort sensor."
echo ""
echo "  Useful commands:"
echo "    ${COMPOSE[*]} logs -f backend"
echo "    ${COMPOSE[*]} logs -f frontend"
echo "    ${COMPOSE[*]} restart backend"
echo "    ${COMPOSE[*]} down -v --remove-orphans"
