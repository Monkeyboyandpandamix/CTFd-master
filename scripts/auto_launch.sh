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
require_command git

clone_if_missing() {
  local url="$1"
  local path="$2"
  if [ -d "$path/.git" ] || [ -f "$path/.git" ]; then
    return
  fi
  echo "Cloning $url into $path"
  git clone "$url" "$path"
}

ensure_juice_shop_ctf_built() {
  local path="$ROOT_DIR/repos/juice-shop-ctf"
  if [ -f "$path/dist/bin/juice-shop-ctf.js" ]; then
    return
  fi
  echo "Installing and building juice-shop-ctf"
  (cd "$path" && npm install && npm run build)
}

echo "[0/5] Ensuring required content repositories exist"
mkdir -p "$ROOT_DIR/repos"
clone_if_missing "https://github.com/apsdehal/awesome-ctf.git" "$ROOT_DIR/repos/awesome-ctf"
clone_if_missing "https://github.com/pwncollege/ctf-archive.git" "$ROOT_DIR/repos/ctf-archive"
clone_if_missing "https://github.com/pwncollege/challenges.git" "$ROOT_DIR/repos/pwncollege-challenges"
clone_if_missing "https://github.com/picoCTF/start-problem-dev.git" "$ROOT_DIR/repos/start-problem-dev"
clone_if_missing "https://github.com/OWASP/wrongsecrets.git" "$ROOT_DIR/repos/wrongsecrets"
clone_if_missing "https://github.com/juice-shop/juice-shop.git" "$ROOT_DIR/repos/juice-shop"
clone_if_missing "https://github.com/juice-shop/juice-shop-ctf.git" "$ROOT_DIR/repos/juice-shop-ctf"
ensure_juice_shop_ctf_built

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

Optional shared-access environment variables
- CTFD_PUBLIC_URL=https://your-host.example
- JUICE_SHOP_URL=https://your-host.example:3001
- WRONGSECRETS_URL=https://your-host.example:8081
- PICO_WEB_CSS_URL=https://your-host.example:8083
- PICO_ARTIFACTS_URL=https://your-host.example:8084/start-problem-dev

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
