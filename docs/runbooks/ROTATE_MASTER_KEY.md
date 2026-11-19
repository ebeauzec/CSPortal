# Rotate the master key

**Use it when** the rotation date in your key policy arrives, a person who knew the key leaves, or the key may have
leaked. If the key may have leaked, also read [ROTATE_GRID_CREDENTIALS.md](ROTATE_GRID_CREDENTIALS.md): everything the
key protected (grid passwords, tenant passwords, multi-factor secrets) is then exposed to whoever had the key **and**
the database, so change those on the grid as well.

**You need:** access to the secret store, the service stopped for a few minutes, and enough disk for one backup.

**What it does:** decrypts every stored secret with the old key, encrypts it with the new key, signs the audit
checkpoints again with a key derived from the new one, then reports. It is all or nothing: if any value cannot be
decrypted, nothing is changed.

## Steps

1. Make the new key and store it in the secret store next to the old one, labelled:
   ```
   python -m csportal genkey > new.key
   ```
2. Stop the service: `docker compose stop`.
3. Rotate. The old key is in `CSPORTAL_MASTER_KEY`. The command takes a backup first
   (`csportal-before-key-rotation-<time>.db`, still encrypted under the old key).
   ```
   docker compose run --rm -v "$PWD/new.key:/run/new.key:ro" csportal rotate-key --new-key-file /run/new.key
   ```
4. Put the new key in `CSPORTAL_MASTER_KEY` (or the key file) in the secret store and the compose or Kubernetes secret.
5. Start: `docker compose up -d`. Delete `new.key` from the working folder.

## Check

- The command printed how many secrets and multi-factor secrets it re-encrypted.
- `python -m csportal verify-audit` prints `intact`.
- Storage grid, **Test these settings first** passes (the grid password opens). A staff user with multi-factor
  authentication can sign in (the multi-factor secret opens).
- Operations shows a backup; make one now so the newest backup is under the new key.

## Go back

Stop the service, restore `csportal-before-key-rotation-<time>.db` ([RESTORE.md](RESTORE.md)) and set the **old** key.
After a successful rotation keep the old key until the last backup made under it is no longer needed.
