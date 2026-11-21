#!/usr/bin/env bash
# Start aplikacji: bash run.sh  (domyślnie nasłuch tylko na 127.0.0.1:8000)
set -e
cd "$(dirname "$0")"
VENV="${ASI_VENV:-$HOME/.venvs/asi}"
[ -d "$VENV" ] || { python3 -m venv "$VENV"; "$VENV/bin/pip" install -q -r requirements.txt; }
exec "$VENV/bin/uvicorn" asi.main:app --host "${ASI_HOST:-127.0.0.1}" --port "${ASI_PORT:-8000}"
