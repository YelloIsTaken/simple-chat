# PyInstaller build recipe for a single-file `simplechat` executable. Used by build.sh.
# -*- mode: python ; coding: utf-8 -*-

# System libraries that every Linux machine already has. Bundling this
# machine's copies is harmful on CachyOS, whose builds target newer CPUs
# (x86-64-v4) and crash with "Illegal instruction" on older ones.
SYSTEM_LIBS = ("libgcc_s.so",)

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# Textual imports its widgets lazily ("from textual.widgets import Button" goes
# through a module __getattr__), and Rich loads Unicode width tables by version
# at runtime. PyInstaller's import scanner can't see either, so list them all.
hidden = collect_submodules("textual") + collect_submodules("rich")

a = Analysis(
    ["chat.py"],
    pathex=[],
    binaries=[],
    datas=collect_data_files("textual"),
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
a.binaries = [b for b in a.binaries if not b[0].startswith(SYSTEM_LIBS)]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="simplechat",
    debug=False,
    strip=False,
    upx=False,
    console=True,
)
