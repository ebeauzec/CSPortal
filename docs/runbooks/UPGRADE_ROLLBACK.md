# Upgrade and roll back

**Use it when** you install a new version, or must go back to the previous one.

**You need:** the new image, the change record, a maintenance window (the service stops for a short time), and
read access to the [CHANGELOG](../../CHANGELOG.md) entries between the two versions.

## Upgrade

1. Read the changelog. Note any new setting, any "Changed" line and any "Not verified" line.
2. Back up: Operations, **Back up now** (or `docker compose exec csportal python -m csportal backup`). Confirm it
   says written and checked. Copy it off the host.
3. Note the current image tag. Pull or build the new image.
4. Stop and start with the new image: `docker compose up -d`. Migrations run at start-up and only move forward.
5. Check: System health shows the new version and schema version; `/healthz` answers; sign in as a staff user and as
   a customer; `python -m csportal verify-audit` prints `intact`; the connector check
   (`python -m csportal conformance`) has no new failures.

## Roll back

A schema migration cannot be undone by starting the old image. To go back:

1. Stop the service.
2. Restore the backup from step 2 with [RESTORE.md](RESTORE.md) (same master key as the backup).
3. Start the previous image tag.

Anything done in the portal after the backup (new customers, bucket changes made through the portal) is not in the
restored database. The grid still holds those changes. Run [DRIFT.md](DRIFT.md) afterwards and fix the differences by hand.

## Python versions

The image uses Python 3.12. A new Python minor version is a deliberate change: run the test suite on it, then change
the Dockerfile, CI and the docs in one commit.
