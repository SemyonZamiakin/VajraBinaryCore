#!/usr/bin/env bash
# Copies the Windows working tree into ~/vajra inside WSL (local helper).
set -euo pipefail
SRC=/mnt/d/Quasar_Soft/VajraBinaryCore
DST="$HOME/vajra"
mkdir -p "$DST"
rsync -a --delete --exclude build* --exclude .git "$SRC"/ "$DST"/
