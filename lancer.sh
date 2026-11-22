#!/usr/bin/env bash
DOSSIER="$(cd "$(dirname "$0")" && pwd)"
cd "$DOSSIER" || exit 1

installe_paquets() {
  if command -v apt-get >/dev/null; then
    sudo apt-get update
    sudo apt-get install -y python3 python3-venv opensc opensc-pkcs11 pcscd libengine-pkcs11-openssl openssl
    sudo systemctl enable --now pcscd
  elif command -v dnf >/dev/null; then
    sudo dnf install -y python3 opensc pcsc-lite openssl openssl-pkcs11
    sudo systemctl enable --now pcscd
  elif command -v pacman >/dev/null; then
    sudo pacman -S --needed --noconfirm python opensc pcsclite openssl libp11
    sudo systemctl enable --now pcscd
  elif command -v zypper >/dev/null; then
    sudo zypper install -y python3 opensc pcsc-lite openssl libp11-3
    sudo systemctl enable --now pcscd
  else
    echo "Distribution non reconnue : installer Python 3, OpenSC, pcscd et openssl a la main."
    exit 1
  fi
}

if ! command -v pkcs11-tool >/dev/null || ! command -v python3 >/dev/null || ! openssl engine -t pkcs11 2>&1 | grep -q available; then
  installe_paquets
fi

if [ ! -d venv ]; then
  python3 -m venv venv || { echo "Echec creation venv"; exit 1; }
  ./venv/bin/pip install --upgrade pip
  ./venv/bin/pip install pyhanko python-pkcs11 pyhanko-certvalidator
fi

exec ./venv/bin/python signature_gui.py "$@"