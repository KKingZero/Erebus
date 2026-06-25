#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TC="${ROOT}/.toolchain/llvm-mingw"

if [[ -x "${TC}/bin/x86_64-w64-mingw32-gcc" ]]; then
  echo "C toolchain already installed at ${TC}"
  exit 0
fi

mkdir -p "${ROOT}/.toolchain"
URL="https://github.com/mstorsjo/llvm-mingw/releases/download/20260616/llvm-mingw-20260616-ucrt-ubuntu-22.04-x86_64.tar.xz"
echo "Downloading llvm-mingw..."
curl -fL "$URL" | tar -xJ -C "${ROOT}/.toolchain"
mv "${ROOT}/.toolchain/llvm-mingw-"* "${TC}" 2>/dev/null || true
if [[ ! -x "${TC}/bin/x86_64-w64-mingw32-gcc" ]]; then
  # archive may extract flat
  for d in "${ROOT}/.toolchain"/llvm-mingw*; do
    if [[ -x "${d}/bin/x86_64-w64-mingw32-gcc" ]]; then
      ln -sfn "$(basename "$d")" "${TC}" 2>/dev/null || mv "$d" "${TC}"
      break
    fi
  done
fi

echo "Installed: ${TC}/bin/x86_64-w64-mingw32-gcc"
"${TC}/bin/x86_64-w64-mingw32-gcc" --version | head -1