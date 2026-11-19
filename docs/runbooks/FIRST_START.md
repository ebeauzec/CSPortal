# First start

**Use it when** you install the portal for the first time.

**You need:** a host with Docker, a reverse proxy with a certificate for the customer portal's public name, a private
network for the admin console, the grid's admin-node CA certificate, the grid provisioning user and its password, and
a secret store.

## Steps

1. Make the master key and put it in the secret store. Keep it apart from the data and from backups.
   ```
   python -m csportal genkey
   ```
2. Copy `deploy/config.example.json` to `deploy/config.json`. Set `public_url`, `admin_public_url`, branding and the
   mail relay. Leave the grid connection out; you enter it in the console.
3. Set `CSPORTAL_MASTER_KEY` and `CSPORTAL_GRID_PASSWORD` in the environment of the service, not in the file.
4. Start: `docker compose up -d`. Open `https://<public name>/healthz` through the proxy: it must answer `ok`.
5. Create the first administrator and open the printed link from the private network.
   ```
   docker compose exec csportal python -m csportal init-admin --email you@example.net --name "Your Name"
   ```
   Set a password and set up multi-factor authentication.
6. Create a **second** super administrator under Staff users. Then open All settings, Security, and switch on
   `security.four_eyes`. (With one super administrator the option cannot work.)
7. Open **Storage grid**. Enter the admin nodes, account, user, password, CA certificates and S3 endpoints. Press
   **Test these settings first**, then **Save and apply**. Give the downloaded sheet to the grid administrators.
8. Run the connector check: `docker compose exec csportal python -m csportal conformance`. Every call must be `ok`.
9. Work through [VERIFY_ON_REAL_GRID.md](VERIFY_ON_REAL_GRID.md) on a non-production grid before any customer is created.

## Check

- System health shows the grid reachable, the audit chain intact, and the jobs with a status after a few minutes.
- Operations shows a backup within 24 hours (or press **Back up now**).
- `docker compose exec csportal python -m csportal verify-audit` prints `intact`.

## Go back

Stop the service and remove the data volume. Nothing outside the volume was changed. The grid has no objects from the
portal until you create a customer.
