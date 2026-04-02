#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILES=(-f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.ctf-content.yml")

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_command docker
require_command python3
require_command node

if [ ! -f "$ROOT_DIR/repos/juice-shop-ctf/dist/bin/juice-shop-ctf.js" ]; then
  echo "Missing juice-shop-ctf build output at repos/juice-shop-ctf/dist/bin/juice-shop-ctf.js" >&2
  echo "Install and build the exporter first, then rerun this launcher." >&2
  exit 1
fi

echo "[1/5] Generating picoCTF artifacts"
cd "$ROOT_DIR"
python3 scripts/generate_pico_artifacts.py --output-root .generated/artifacts

echo "[2/5] Building Juice Shop and WrongSecrets challenge exports"
node repos/juice-shop-ctf/dist/bin/juice-shop-ctf.js \
  --config "$ROOT_DIR/conf/ctf-content/juice-shop.yml" \
  --output "$ROOT_DIR/.generated/juice-shop.csv"
node repos/juice-shop-ctf/dist/bin/juice-shop-ctf.js \
  --config "$ROOT_DIR/conf/ctf-content/wrongsecrets.yml" \
  --output "$ROOT_DIR/.generated/wrongsecrets.csv"

echo "[3/5] Building integrated challenge catalog"
python3 scripts/build_integrated_challenges.py \
  --juice-shop-csv .generated/juice-shop.csv \
  --wrongsecrets-csv .generated/wrongsecrets.csv \
  --output-csv .generated/integrated-challenges.csv \
  --runtime-env .generated/runtime.env

echo "[4/5] Starting Docker services"
docker compose "${COMPOSE_FILES[@]}" up -d --build

echo "[5/5] Seeding CTFd with integrated content"
docker compose "${COMPOSE_FILES[@]}" exec -T ctfd sh -lc \
  'cd /opt/CTFd && PYTHONPATH=/opt/CTFd /opt/venv/bin/python scripts/seed_ctfd_content.py'

cat <<'EOF'

Auto-launch completed.

Main URLs
- CTFd: http://localhost:8000
- Nginx: http://localhost
- Repo review: http://localhost:8000/repo-review
- Juice Shop: http://localhost:3001
- WrongSecrets: http://localhost:8081
- pico Web CSS: http://localhost:8083
- pico Artifacts: http://localhost:8084/start-problem-dev
- Canvas LTI admin: http://localhost:8000/admin/canvas-lti

Local admin login
- Email: admin@example.com
- Password: AdminPass123!

EOF
