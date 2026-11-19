# CSPortal on Kubernetes

**Status: written, not tested on a cluster.** The manifests follow the image's documented behaviour (non-root user
10001, read-only root file system, port 8443 customer, port 8444 admin, `/healthz`, data in `/data`). Apply them first
to a test cluster and walk through [../../docs/runbooks/FIRST_START.md](../../docs/runbooks/FIRST_START.md). Record what you had to change.

## The one rule: exactly one replica

CSPortal keeps its data in an embedded SQLite database on a volume. Two pods writing to it would corrupt it, so:

- `replicas: 1` in the StatefulSet. Never scale it.
- The volume is `ReadWriteOnce`. Do not use a `ReadWriteMany` class to "make scaling work".
- Rolling updates stop the old pod before the new one starts (a StatefulSet does this); expect a short outage during an
  upgrade and a node failure.
- If the node fails, Kubernetes starts the pod elsewhere only when the volume can follow it (network block storage,
  not node-local disks). Choose a storage class that is backed up and survives node loss.

High availability beyond that needs a server database, which is on the roadmap (Release 3).

## Files

| File | Contains |
|---|---|
| `namespace-and-services.yaml` | Namespace with the `restricted` pod security level, the customer and admin services (ClusterIP), a headless service, a network policy |
| `config-and-secrets.example.yaml` | Configuration, the grid CA certificate, the secrets, and the customer ingress. A template: fill it in and keep your copy out of git |
| `statefulset.yaml` | The pod: one replica, restricted security context, probes, volume claim |

## Install

1. Build and push the image (`docker build -t registry.example.net/csportal:0.1.0 .`) and put its name in `statefulset.yaml`.
2. Make the master key (`python -m csportal genkey`) and store it in your secret store. Create the
   `csportal-secrets` Secret from there, or fill in the example file for a test cluster.
3. Apply: `kubectl apply -f namespace-and-services.yaml`, then your filled-in secrets and configuration file, then `statefulset.yaml`.
4. Create the first administrator:
   ```
   kubectl -n csportal exec csportal-0 -- python -m csportal init-admin --email you@example.net --name "Your Name"
   ```
5. Reach the admin console from a private place only: `kubectl -n csportal port-forward csportal-0 8444:8444`, or a
   private ingress on your management network. **Never** add the admin service to the public ingress. The console also
   refuses any request that carries proxy headers unless `admin_allow_proxy` is set; leave it off.

## Operations

| Task | Command |
|---|---|
| Any CLI command | `kubectl -n csportal exec csportal-0 -- python -m csportal <command>` |
| Backup now | `kubectl -n csportal exec csportal-0 -- python -m csportal backup`, then copy `/data/backups/` off the volume (`kubectl cp`) or use volume snapshots **and** the portal's own backups |
| Rotate the master key | Scale to zero (`kubectl -n csportal scale statefulset csportal --replicas=0`), run the rotation in a one-off pod that mounts the same volume and the new key file, update the Secret, scale back to one. See [ROTATE_MASTER_KEY](../../docs/runbooks/ROTATE_MASTER_KEY.md) |
| Logs | `kubectl -n csportal logs csportal-0` (the application log also goes to standard output as JSON lines); files are kept in `/data/logs`; set `log.syslog` to forward to a collector |

Keep logs outside the pod as well (your cluster's log shipper reads standard output). The audit log is in the database, not in these logs.

## Hardening you still own

- Pod security level `restricted` is set on the namespace; the pod complies.
- The network policy limits traffic. Edit its selectors and the egress addresses (the sample uses a documentation range).
- Scan the image (CI does for Python packages) and the cluster nodes yourself.
- Protect the Secret: restrict who can read it, encrypt secrets at rest in etcd, and keep the master key out of the cluster
  backup that also holds the data volume.
