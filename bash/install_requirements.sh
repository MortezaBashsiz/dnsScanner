#!/usr/bin/env bash

#===============================================================================
#
#          FILE: install_requirements.sh
#   DESCRIPTION: Install dependencies for dnsScanner.sh
#  REQUIREMENTS: A supported package manager (apt, dnf, yum, pacman, zypper, brew)
#===============================================================================

set -euo pipefail

REQUIRED_CMDS=(
  jq
  parallel
  bc
  curl
  git
  getopt
  tput
  timeout
  dig
  shuf
)

detect_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  elif command -v pacman >/dev/null 2>&1; then
    echo "pacman"
  elif command -v zypper >/dev/null 2>&1; then
    echo "zypper"
  elif command -v brew >/dev/null 2>&1; then
    echo "brew"
  else
    echo "unknown"
  fi
}

install_with_apt() {
  sudo apt-get update
  sudo apt-get install -y \
    jq parallel bc curl git \
    util-linux dnsutils coreutils \
    psmisc ncurses-bin
}

install_with_dnf() {
  sudo dnf install -y \
    jq parallel bc curl git \
    util-linux bind-utils coreutils \
    psmisc ncurses
}

install_with_yum() {
  sudo yum install -y \
    jq parallel bc curl git \
    util-linux bind-utils coreutils \
    psmisc ncurses
}

install_with_pacman() {
  sudo pacman -Sy --needed --noconfirm \
    jq parallel bc curl git \
    util-linux bind coreutils \
    psmisc ncurses
}

install_with_zypper() {
  sudo zypper install -y \
    jq parallel bc curl git \
    util-linux bind-utils coreutils \
    psmisc ncurses
}

install_with_brew() {
  brew update
  brew install jq parallel bc curl git coreutils findutils gnu-getopt bind
}

main() {
  missing=()
  for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done

  if [ "${#missing[@]}" -eq 0 ]; then
    echo "All required commands are already installed:"
    printf '  %s\n' "${REQUIRED_CMDS[@]}"
    exit 0
  fi

  echo "Missing commands:"
  printf '  %s\n' "${missing[@]}"

  pmgr=$(detect_package_manager)
  echo "Detected package manager: $pmgr"

  case "$pmgr" in
    apt)    install_with_apt ;;
    dnf)    install_with_dnf ;;
    yum)    install_with_yum ;;
    pacman) install_with_pacman ;;
    zypper) install_with_zypper ;;
    brew)   install_with_brew ;;
    *)
      echo "Could not detect a supported package manager."
      echo "Please install these commands manually:"
      printf '  %s\n' "${missing[@]}"
      exit 1
      ;;
  esac

  echo
  echo "Re-checking installed commands..."
  for cmd in "${REQUIRED_CMDS[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      printf '  [OK] %s\n' "$cmd"
    else
      printf '  [MISSING] %s (install manually)\n' "$cmd"
    fi
  done
}

main "$@"

