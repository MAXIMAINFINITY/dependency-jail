#!/usr/bin/env bash
# setup.sh — dependency-jail virtual environment setup
# Run from inside the dependency-jail directory:
#   chmod +x setup.sh && ./setup.sh

set -euo pipefail

PROJ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJ_DIR"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   dependency-jail  •  Setup Script   ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# ── 1. Check python3 ──────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "  [ERROR] python3 not found. Install it first:"
    echo "    sudo apt install python3 python3-venv python3-pip"
    exit 1
fi
echo "  ✓  python3 found: $(python3 --version)"

# ── 2. Check gcc ──────────────────────────────────────────────────────────────
if ! command -v gcc &>/dev/null; then
    echo "  [WARN]  gcc not found. Installing build-essential…"
    sudo apt-get install -y build-essential
fi
echo "  ✓  gcc found: $(gcc --version | head -1)"

# ── 3. Create virtual environment ────────────────────────────────────────────
if [ ! -d ".venv" ]; then
    echo "  ⚙  Creating virtual environment at .venv …"
    python3 -m venv .venv
else
    echo "  ✓  Virtual environment already exists (.venv)"
fi

# ── 4. Activate ───────────────────────────────────────────────────────────────
# shellcheck disable=SC1091
source .venv/bin/activate
echo "  ✓  Activated: $VIRTUAL_ENV"

# ── 5. Upgrade pip silently ───────────────────────────────────────────────────
pip install --quiet --upgrade pip

# ── 6. Install dependency-jail in editable mode ───────────────────────────────
echo "  ⚙  Installing dependency-jail (editable) …"
pip install -e .
echo "  ✓  Installed"

# ── 7. Compile the interceptor library ───────────────────────────────────────
echo ""
echo "  ⚙  Compiling libjail.so …"
dep-jail --compile-only
echo ""

# ── 8. Quick smoke test ───────────────────────────────────────────────────────
echo "  🧪  Running smoke test: dep-jail --dry-run pip install requests"
echo ""
dep-jail --dry-run pip install requests
echo ""

# ── Done ──────────────────────────────────────────────────────────────────────
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║  Setup complete!                                     ║"
echo "  ║                                                      ║"
echo "  ║  To activate the env in a new shell:                 ║"
echo "  ║    source .venv/bin/activate                         ║"
echo "  ║                                                      ║"
echo "  ║  Usage:                                              ║"
echo "  ║    dep-jail pip install <package>                    ║"
echo "  ║    dep-jail npm install                              ║"
echo "  ║    dep-jail --verbose pip install -r requirements.txt║"
echo "  ║                                                      ║"
echo "  ║  Run tests:                                          ║"
echo "  ║    python -m pytest tests/ -v                        ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo ""
