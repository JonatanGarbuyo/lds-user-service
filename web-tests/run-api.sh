#!/usr/bin/env bash
set -euo pipefail

if command -v go >/dev/null 2>&1; then
  exec go run ./cmd/server
fi

outbox="${MAIL_OUTBOX_FILE:-/tmp/lds-user-service-browser-mail/outbox.jsonl}"
mkdir -p "$(dirname "$outbox")"
touch "$outbox"
chmod 0666 "$outbox"

name="lds-user-service-browser-api-$$"
docker run --rm --name "$name" --label lds-user-service-browser-api=1 --network host \
  -v "$PWD":/src \
  -v lds-go-mod:/go/pkg/mod \
  -v lds-go-build:/root/.cache/go-build \
  -v "$(dirname "$outbox")":"$(dirname "$outbox")" \
  -w /src \
  -e APP_ENV="${APP_ENV:-development}" \
  -e HTTP_ADDR="${HTTP_ADDR:-:8090}" \
  -e DATABASE_URL="${DATABASE_URL:-postgres://lds:lds_dev_password@127.0.0.1:5432/lds_user_service?sslmode=disable}" \
  -e CORS_ALLOWED_ORIGINS="${CORS_ALLOWED_ORIGINS:-http://app.lds.test:4173}" \
  -e MAIL_OUTBOX_FILE="$outbox" \
  -e EMAIL_VERIFICATION_REQUIRED="${EMAIL_VERIFICATION_REQUIRED:-true}" \
  golang:1.26.4-alpine go run ./cmd/server &
pid=$!

cleanup() {
  docker stop "$name" >/dev/null 2>&1 || true
  wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait "$pid"
