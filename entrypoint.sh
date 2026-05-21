#!/bin/sh
# Container entrypoint: apply database migrations, then start the app.
#
# Running `alembic upgrade head` here means a fresh deployment gets its schema
# automatically — no manual migration step to forget. It is idempotent: a no-op
# when the database is already at head. Skipped when no database is configured.
#
# A migration failure is logged but NOT fatal: the API still starts (it already
# tolerates a missing/unreachable DB), so a migration hiccup degrades
# persistence rather than taking the whole service down.
set -e

# The `alembic` console script does not add the working dir to sys.path the way
# `python -m` does, so env.py cannot import `terravault` without this.
export PYTHONPATH="/app:${PYTHONPATH:-}"

if [ -n "${TERRAVAULT_DATABASE_URL:-}" ]; then
	echo "[entrypoint] applying database migrations (alembic upgrade head)"
	if alembic upgrade head; then
		echo "[entrypoint] migrations applied"
	else
		echo "[entrypoint] WARNING: migrations failed; starting API anyway (persistence may be degraded)" >&2
	fi
else
	echo "[entrypoint] TERRAVAULT_DATABASE_URL unset — skipping migrations"
fi

exec "$@"
