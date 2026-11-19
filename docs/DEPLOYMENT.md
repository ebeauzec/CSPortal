# Deployment

CSPortal is one image and one process. This page covers a production install. For a demonstration see
[DEMO.md](DEMO.md).

## What you need

- A host or VM with Docker (or Python 3.12 and `pip install -r requirements.txt`).
- A StorageGRID system whose Grid Management API is reachable from the host, and an admin-node
  certificate chain (or the CA certificate that signed it).
- A grid group and user for the portal's **provisioning identity** with only the permissions needed to
  manage tenant accounts (see [STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md)). Never use the
  grid's root account.
- A reverse proxy (or load balancer) with a certificate for the customer portal's public name.
- A private network or VPN for the admin console.
- An SMTP relay if the portal should send invitations and alerts.

## Steps

1. **Make a master key and keep it apart from the data.**
   ```
   python -m csportal genkey
   ```
   Store it in your secret store. It encrypts every stored credential. Losing it means re-entering them.
2. **Write the configuration.** Copy `deploy/config.example.json` to `deploy/config.json` and set the public URL,
   grid address, CA file, S3 endpoint, mail relay and branding. Production mode refuses to start unless TLS is
   handled (`behind_proxy` or certificates), the grid URL is `https://`, certificate checking is on, and the
   admin console is not on a public address.
3. **Set the secrets as environment variables** (not in the file): `CSPORTAL_MASTER_KEY`,
   `CSPORTAL_GRID_PASSWORD`, and `CSPORTAL_SMTP_PASSWORD` if used.
4. **Start.**
   ```
   docker compose up -d
   ```
   The customer portal listens on 8443 (behind your proxy); the admin console on 8444 on a private address.
5. **Check the connector before you trust it.**
   ```
   docker compose exec csportal python -m csportal conformance
   ```
   Every call the connector uses must report `ok` against your grid's own API description. Fix or report any that
   do not. Until the connector has been verified on your release, run it against a non-production grid first.
6. **Create the first administrator.**
   ```
   docker compose exec csportal python -m csportal init-admin --email you@example.net --name "Your Name"
   ```
   Open the printed link from the private network, set a password, and set up multi-factor authentication.
7. **Configure in the admin console:** branding, plans (price, quota, features), then create a test customer
   and walk through the customer journey.

## Network layout

| Listener | Default | Exposure |
|---|---|---|
| Customer portal | `0.0.0.0:8443` | Behind the reverse proxy and web application firewall; public |
| Admin console | `127.0.0.1:8444` | Private network only. It refuses any request carrying proxy headers |
| Outbound | Grid admin API, S3 endpoint, mail relay | Nothing else. No telemetry |

## Backup and restore

- **Backup:** `python -m csportal backup` (or the System page) writes a consistent database copy to
  `data/backups/`. Copy it off the host. Store the master key separately.
- **Restore:** stop the service, put the database file back as `data/csportal.db`, start with the same master key.
- **Check:** `python -m csportal verify-audit` confirms the audit chain is intact after a restore.

## Upgrade

Take a backup, replace the image, start. Migrations run at start-up and only move forward. Roll back by
restoring the backup and starting the previous image.

## Hardening checklist

- [ ] Customer portal only reachable through the proxy; admin console on a private address.
- [ ] Master key in a secret store; not in the config file, image, repository or backups.
- [ ] Grid provisioning identity has least privilege; its password is rotated on a schedule.
- [ ] Grid CA certificate supplied; certificate checking on.
- [ ] Container runs as non-root, read-only file system, no extra capabilities (the compose file does this).
- [ ] Log forwarding configured (`log.syslog`) and log files rotated off the host.
- [ ] Multi-factor authentication required for customers (default) and enforced for staff.
- [ ] Mail relay tested: send an invitation to yourself.
- [ ] Backups tested by restoring them on another host.

## Limits of this release

Single node with an embedded database (no clustering). No single sign-on for staff. Not yet penetration
tested. The StorageGRID connector is not yet verified on a real grid. See [STATUS](../README.md#status).
