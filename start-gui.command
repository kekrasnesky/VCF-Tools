#!/bin/sh
# Double-click this file in Finder to open VCF Diagnostics in your browser.
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 was not found. Install the Xcode Command Line Tools with:  xcode-select --install"
  printf "Press Return to close. "; read -r _
  exit 1
fi
exec python3 vcf_diag.py --gui
