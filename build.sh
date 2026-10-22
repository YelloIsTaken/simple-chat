#!/usr/bin/env bash
# Build a single self-contained executable at dist/simplechat with PyInstaller.
# The result runs without Python installed, but only on the same OS/CPU type
# it was built on (build on Windows for a .exe, on macOS for a Mac binary).
#
# PyInstaller copies the Python interpreter it runs under into the executable.
# CachyOS's Python is compiled for newer CPUs (x86-64-v3/v4, e.g. AVX-512),
# which crashes with "Illegal instruction" on older processors. So the build
# uses a portable, baseline x86-64 Python downloaded by uv instead.
set -euo pipefail
cd "$(dirname "$0")"

BUILD_PYTHON=cpython-3.13-linux-x86_64-gnu   # baseline x86-64, no -v3/-v4 suffix

if ! command -v uv >/dev/null; then
    echo "uv is required: sudo pacman -S uv   (or: pipx install uv)" >&2
    exit 1
fi
uv python install "$BUILD_PYTHON"
if [ ! -d .venv-build ]; then
    uv venv --python "$BUILD_PYTHON" .venv-build
fi
uv pip install --python .venv-build -q -r requirements.txt pyinstaller

.venv-build/bin/pyinstaller --clean --noconfirm simplechat.spec
echo
echo "Built: dist/simplechat"
