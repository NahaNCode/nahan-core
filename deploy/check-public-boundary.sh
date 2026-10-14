#!/bin/sh
set -eu

# Operational files must stay in the private deployment repository.
blocked=$(git ls-files | awk '/(^|\/)(agent|core)\.key$|(^|\/)\.env$|(^|\/)runtime\/|^deploy\/(destination-.*-override\.conf|xray-.*|lab-public.*|nahan-lab\.service)$|^lab\/(admin|public_tls|verify_receipts)\.py$/')
if [ -n "$blocked" ]; then
  printf '%s\n' 'Public repository contains operational files:' "$blocked" >&2
  exit 1
fi
