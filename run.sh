#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APP_FILE="main.py"
VENV_DIR=".venv"
REQ_FILE="requirements.txt"
CATALOG_FILE="software_catalog.json"

echo "[*] Starting CTF-Scout modular..."
echo "[*] Folder: $SCRIPT_DIR"

if [[ "${XDG_SESSION_TYPE:-}" == "wayland" ]]; then
  echo "[!] Warning: this tool works best on X11 / standard session."
fi

install_pkg_if_missing() {
  local cmd="$1"
  local pkg="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[+] Installing $pkg..."
    sudo apt-get install -y "$pkg"
  else
    echo "[=] Found: $cmd"
  fi
}

echo "[*] Updating apt index..."
sudo apt-get update -y

echo "[*] Checking system dependencies..."
install_pkg_if_missing python3 python3
install_pkg_if_missing pip3 python3-pip
install_pkg_if_missing tesseract tesseract-ocr
install_pkg_if_missing wmctrl wmctrl
install_pkg_if_missing xdotool xdotool
install_pkg_if_missing xwininfo x11-utils
install_pkg_if_missing searchsploit exploitdb

if ! python3 -c "import tkinter" >/dev/null 2>&1; then
  echo "[+] Installing python3-tk..."
  sudo apt-get install -y python3-tk
fi

if ! python3 -c "import venv" >/dev/null 2>&1; then
  echo "[+] Installing python3-venv..."
  sudo apt-get install -y python3-venv
fi

if [[ ! -d "$VENV_DIR" ]]; then
  echo "[*] Creating virtual environment..."
  python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip setuptools wheel
pip install -r "$REQ_FILE"

if [[ ! -f "$CATALOG_FILE" ]]; then
  echo "[*] software_catalog.json will be created on first launch."
fi

python "$APP_FILE"
