#!/usr/bin/env bash
set -euo pipefail

echo "[*] Installing system dependencies (Debian/Ubuntu)..."
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y nmap curl git
fi

echo "[*] Installing Python package..."
python3 -m pip install -e ".[dev]"

echo "[*] Checking external tools..."
for tool in nmap nuclei naabu ffuf; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  [ok] $tool"
  else
    echo "  [missing] $tool (optional but recommended)"
  fi
done

echo "[*] Done. Run: roastmywebsite doctor"