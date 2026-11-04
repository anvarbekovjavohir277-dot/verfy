#!/bin/sh
# Installs the standalone verfy CLI. Python is included; nothing else is needed.
#
#   curl -fsSL https://verfy.dev/install.sh | sh
#
# Environment: VERFY_VERSION=0.2.0 pins a version; VERFY_INSTALL_DIR (default
# ~/.local/share/verfy) and VERFY_BIN_DIR (default ~/.local/bin) move it;
# VERFY_NO_MODIFY_PATH=1 leaves your shell profile alone; VERFY_DOWNLOAD_BASE
# replaces the release URL (a mirror, or a local test server).
# Builds: https://github.com/anvarbekovjavohir277-dot/verfy-releases
set -eu

REPO="anvarbekovjavohir277-dot/verfy-releases"

say() { printf 'verfy: %s\n' "$*"; }
fail() { printf 'verfy: error: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64 | Linux/amd64) target=linux-x64 ;;
  Linux/aarch64 | Linux/arm64) target=linux-arm64 ;;
  Darwin/arm64) target=macos-arm64 ;;
  Darwin/x86_64)
    # a terminal running under Rosetta on Apple silicon still runs the arm64 build
    [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ] || fail "there is no standalone build for Intel Macs yet; use: pip install verfy (Python 3.10+)"
    target=macos-arm64 ;;
  *) fail "there is no standalone build for $(uname -s) $(uname -m); use: pip install verfy (Python 3.10+)" ;;
esac

if command -v curl >/dev/null 2>&1; then
  dl() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  dl() { wget -q --https-only -O "$2" "$1"; }
else
  fail "curl or wget is needed"
fi

if [ -n "${VERFY_DOWNLOAD_BASE:-}" ]; then
  base="$VERFY_DOWNLOAD_BASE"
elif [ -n "${VERFY_VERSION:-}" ]; then
  base="https://github.com/$REPO/releases/download/v$VERFY_VERSION"
else
  base="https://github.com/$REPO/releases/latest/download"
fi
file="verfy-$target.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $file"
dl "$base/$file" "$tmp/$file" || fail "could not download $base/$file"
dl "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download $base/SHA256SUMS"

want=$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$want" ] || fail "$file is not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$file" | awk '{ print $1 }')
else
  got=$(shasum -a 256 "$tmp/$file" | awk '{ print $1 }')
fi
[ "$got" = "$want" ] || fail "checksum mismatch for $file; nothing was installed"

tar -xzf "$tmp/$file" -C "$tmp"
version=$("$tmp/verfy/verfy" --version 2>/dev/null | awk '{ print $2 }') || true
[ -n "$version" ] || fail "the downloaded verfy does not run on this system; use: pip install verfy"

root="${VERFY_INSTALL_DIR:-$HOME/.local/share/verfy}"
bin="${VERFY_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$root" "$bin"
rm -rf "$root/$version"
mv "$tmp/verfy" "$root/$version"
ln -sf "$root/$version/verfy" "$bin/verfy"
say "installed verfy $version in $root/$version"

case ":$PATH:" in
  *":$bin:"*) ;;
  *)
    line="export PATH=\"$bin:\$PATH\""
    if [ -n "${VERFY_NO_MODIFY_PATH:-}" ]; then
      say "$bin is not on your PATH; add this line to your shell profile: $line"
    else
      case "$(basename "${SHELL:-sh}")" in
        zsh) profile="$HOME/.zshrc" ;;
        bash) if [ "$(uname -s)" = Darwin ]; then profile="$HOME/.bash_profile"; else profile="$HOME/.bashrc"; fi ;;
        *) profile="$HOME/.profile" ;;
      esac
      if ! grep -qsF "$line" "$profile"; then
        printf '\n# added by the verfy installer\n%s\n' "$line" >> "$profile"
        say "added $bin to your PATH in $profile"
      fi
      say "open a new terminal, or run: $line"
    fi
    ;;
esac

say "next: verfy init && verfy hook install"
