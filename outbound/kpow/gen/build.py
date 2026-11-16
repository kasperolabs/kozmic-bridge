#!/usr/bin/env python3
"""Builds sol/src/KaspaPow.sol from gen/KaspaPow.sol.in plus the generated keccak-f[1600] Yul."""
import pathlib, subprocess, sys
here = pathlib.Path(__file__).resolve().parent
subprocess.run([sys.executable, str(here / "gen_keccak.py")], check=True)
src = (here / "KaspaPow.sol.in").read_text()
inc = (here / "keccak.yul.inc").read_text().rstrip("\n")
out = here.parent / "sol" / "src" / "KaspaPow.sol"
out.write_text(src.replace("@@KECCAK@@", inc))
print("wrote", out)
