#!/bin/sh
# Container entrypoint: apply database migrations, then start the app.
#
# Running `alembic upgrade head` here means a fresh deployment gets its schema
# automatically — no manual migration step to forget. It is idempotent: a no-op
# when the database is already at head. Skipped when no database is configured
# (e.g. local CLI-only runs).
set -e

if [ -n "${TERRAVAULT_DATABASE_URL:-}" ]; then
	echo "[entrypoint] applying database migrations (alembic upgrade head)"
	alembic upgrade head
else
	echo "[entrypoint] TERRAVAULT_DATABASE_URL unset — skipping migrations"
fi

exec "$@"
