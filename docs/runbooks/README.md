# Runbooks

One page per task. Each page says when to use it, what you need, the steps, how to check the result and how to go
back. Commands assume the Docker Compose install in [DEPLOYMENT.md](../DEPLOYMENT.md); on Kubernetes use
`kubectl exec` or a one-off pod in place of `docker compose exec` (see [deploy/kubernetes/README.md](../../deploy/kubernetes/README.md)).

| Runbook | Use it when |
|---|---|
| [FIRST_START.md](FIRST_START.md) | You install the portal for the first time |
| [VERIFY_ON_REAL_GRID.md](VERIFY_ON_REAL_GRID.md) | You connect the portal to a real StorageGRID for the first time, or after a grid upgrade |
| [UPGRADE_ROLLBACK.md](UPGRADE_ROLLBACK.md) | You install a new version, or must go back |
| [RESTORE.md](RESTORE.md) | The data is lost or damaged; also the quarterly restore test |
| [ROTATE_MASTER_KEY.md](ROTATE_MASTER_KEY.md) | Scheduled rotation, or the key may have leaked |
| [ROTATE_GRID_CREDENTIALS.md](ROTATE_GRID_CREDENTIALS.md) | The portal's grid password or a customer's tenant password changes |
| [DIAGNOSTICS.md](DIAGNOSTICS.md) | Something fails and someone else must fix it remotely |
| [DRIFT.md](DRIFT.md) | The drift check reports a difference between the portal and the grid |
| [AUDIT_RETENTION.md](AUDIT_RETENTION.md) | You manage audit archives, or the audit check reports a problem |

Rules for every runbook: take a backup before you change anything; change one thing at a time; write down what you did
and the time in your own change record; if a step does not give the stated result, stop and use
[DIAGNOSTICS.md](DIAGNOSTICS.md).
