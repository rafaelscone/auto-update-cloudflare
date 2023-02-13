#!/bin/bash
# crontab -e
# */15 * * * * /opt/cf-dns-update-python/run.sh
cd "$(dirname "$0")"

if command -v python3 &>/dev/null; then
    python3 index.py $@
else
    python index.py $@
fi