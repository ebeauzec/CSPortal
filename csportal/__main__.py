"""Command line: python -m csportal <command>

  serve        run both surfaces and the job runner
  demo         run in demo mode (simulated storage, sample data) in a separate data folder
  genkey       print a new master key
  init-admin   create the first provider administrator and print the set-password link
  selftest     run the built-in checks and exit
  conformance  compare the StorageGRID connector's calls with the grid's own API description
  bundle       write a diagnostic bundle to a file
  backup       write a database backup (checked after writing)
  verify-audit check the audit hash chain, its checkpoints and the retention anchor
  rotate-key   re-encrypt every stored secret under a new master key (stop the service first)
  drift        compare customers and quotas with the tenant accounts on the grid
  person-export  print everything held about one e-mail address (JSON)
  person-erase   remove the accounts and stored mail for one e-mail address
  set-tenant-password  store a new tenant root password after you changed it on the grid (checked first)
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time

from . import __version__, config, crypto
from .web.core import start_server


def _build(args):
    from .bootstrap import build_app
    overrides = {}
    if getattr(args, "demo", False):
        port = args.port or 8443
        overrides = {"mode": "demo", "data_dir": args.data_dir or "./demo-data", "backend": {"type": "simulator"},
                     "public_url": f"http://127.0.0.1:{port}", "admin_public_url": f"http://127.0.0.1:{port + 1}",
                     "customer_listen": {"host": "127.0.0.1", "port": args.port or 8443},
                     "admin_listen": {"host": "127.0.0.1", "port": (args.port or 8443) + 1}}
    elif getattr(args, "port", None):
        overrides = {"customer_listen": {"port": args.port}}
    cfg = config.load(args.config, overrides)
    return cfg, build_app(cfg)


def cmd_serve(args):
    cfg, app = _build(args)
    from .jobs import JobRunner
    jr = JobRunner(app)
    app.job_runner = jr
    jr.start()
    cl, ad, tls = cfg.d["customer_listen"], cfg.d["admin_listen"], cfg.d["tls"]
    servers = [start_server(app, "customer", cl["host"], cl["port"], tls["customer_cert"], tls["customer_key"], cfg.d["behind_proxy"]),
               start_server(app, "admin", ad["host"], ad["port"], tls["admin_cert"], tls["admin_key"], False)]
    scheme = "https" if tls["customer_cert"] else "http"
    print(f"CSPortal {__version__} ({cfg.d['mode']} mode)")
    print(f"  Customer portal : {scheme}://{cl['host']}:{cl['port']}/")
    print(f"  Admin console   : {'https' if tls['admin_cert'] else 'http'}://{ad['host']}:{ad['port']}/  (private)")
    if cfg.demo:
        print("  Demo mode: simulated storage and sample data. Sample accounts are listed on the sign-in pages.")
    stop = threading.Event()
    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, lambda *a: stop.set())
    stop.wait()
    logging.getLogger("csportal").info("shutting down")
    jr.stop()
    for s in servers:
        s.shutdown()


def cmd_genkey(args):
    print(crypto.generate_master_key())


def cmd_init_admin(args):
    cfg, app = _build(args)
    from . import services
    uid = app.auth.create_user(args.email, args.name or args.email, "super-administrator", None, actor="cli")
    tok = app.auth.invite_token(uid, hours=24)
    print("Open this link to set the password (valid for 24 hours, use it once):")
    print(services.invite_link(app, tok, admin=True))


def cmd_conformance(args):
    cfg, app = _build(args)
    if not hasattr(app.backend, "conformance"):
        print("The simulator has no external API to check.")
        return
    rows = app.backend.conformance()
    for r in rows:
        print(f"{r['status']:8} {r['method']:6} {r['path']}  {r['detail']}")
    sys.exit(0 if all(r["status"] == "ok" for r in rows) else 2)


def cmd_bundle(args):
    cfg, app = _build(args)
    from .modules.system import build_bundle
    from pathlib import Path
    out = Path(args.out or "csportal-diagnostics.zip")
    out.write_bytes(build_bundle(app))
    print(f"Wrote {out}")


def cmd_backup(args):
    cfg, app = _build(args)
    from pathlib import Path
    from . import ops
    if args.out:
        dest = Path(args.out)
        app.db.backup(dest)
        state = ops.check_backup(dest)
        print(f"Wrote {dest} (check: {state})")
        sys.exit(0 if state == "ok" else 2)
    r = ops.backup_now(app, keep=0)
    print(f"Wrote {cfg.data_dir / 'backups' / r['file']} ({r['bytes']:,} bytes, check: ok)")


def cmd_verify_audit(args):
    cfg, app = _build(args)
    v = app.audit.verify_full()
    print(f"audit chain: {'intact' if v['ok'] else 'PROBLEM'} ({v['rows']} records, {v['checkpoints']} checkpoints"
          + (f", older records archived up to id {v['anchor_id']}" if v["anchor_id"] else "") + ")")
    for p in v["problems"]:
        print("  - " + p)
    sys.exit(0 if v["ok"] else 2)


def cmd_rotate_key(args):
    import base64
    from pathlib import Path
    from . import ops
    if not args.new_key_file:
        raise SystemExit("Give --new-key-file: a file holding the new key (make one with: python -m csportal genkey > new.key).")
    raw = Path(args.new_key_file).read_text(encoding="utf-8").strip()
    new = base64.b64decode(raw)
    cfg, app = _build(args)
    pre = ops.backup_now(app, keep=0, label="csportal-before-key-rotation")
    print(f"Backup before rotation: {pre['file']}")
    res = ops.rotate_master_key(app, new)
    print(f"Re-encrypted {res['secrets']} stored secret(s) and {res['totp']} multi-factor secret(s); audit checkpoints signed again.")
    print("Now put the NEW key in CSPORTAL_MASTER_KEY (or the key file) and start the service. The old key no longer opens the data.")


def cmd_drift(args):
    from . import ops
    cfg, app = _build(args)
    rep = ops.drift_report(app)
    print(ops.drift_summary(rep))
    for x in rep["missing_on_grid"]:
        print(f"  missing on grid : {x['customer']} ({x['ref']})")
    for x in rep["quota_mismatch"]:
        print(f"  quota differs   : {x['customer']} portal {x['portal_bytes']} bytes, grid {x['grid_bytes']} bytes")
    for x in rep["not_in_portal"]:
        print(f"  not in portal   : {x['name']} ({x['ref']})")
    sys.exit(0 if rep["ok"] else 2)


def cmd_person_export(args):
    import json
    from . import ops
    cfg, app = _build(args)
    print(json.dumps(ops.person_export(app, args.email), indent=2, default=str))


def cmd_person_erase(args):
    from . import ops
    cfg, app = _build(args)
    try:
        r = ops.person_erase(app, args.email, "cli")
    except ValueError as e:
        raise SystemExit(str(e))
    print(f"Removed {r['accounts']} account(s) and {r['mail']} stored mail(s). Audit records stay until retention ends.")


def cmd_set_tenant_password(args):
    """Use after the tenant root password was changed on the grid. The new password is read from the environment
    variable CSPORTAL_NEW_TENANT_PASSWORD or typed in; it is tested against the grid before it is kept."""
    import getpass
    import os
    from . import ops
    cfg, app = _build(args)
    pw = os.environ.get("CSPORTAL_NEW_TENANT_PASSWORD") or getpass.getpass("New tenant root password: ")
    try:
        ops.set_tenant_password(app, args.customer, pw, "cli")
    except ValueError as e:
        raise SystemExit(str(e))
    print("Stored. Restart the service (or wait up to an hour) so running sessions pick up the new password.")


def main(argv=None):
    p = argparse.ArgumentParser(prog="csportal", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default=None, help="path to the JSON configuration file")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in [("serve", cmd_serve), ("demo", cmd_serve), ("genkey", cmd_genkey), ("init-admin", cmd_init_admin),
                     ("conformance", cmd_conformance), ("bundle", cmd_bundle), ("backup", cmd_backup), ("verify-audit", cmd_verify_audit),
                     ("rotate-key", cmd_rotate_key), ("drift", cmd_drift), ("person-export", cmd_person_export), ("person-erase", cmd_person_erase), ("set-tenant-password", cmd_set_tenant_password)]:
        sp = sub.add_parser(name)
        sp.set_defaults(fn=fn, demo=(name == "demo"))
        sp.add_argument("--port", type=int, default=None)
        sp.add_argument("--data-dir", default=None)
        sp.add_argument("--out", default=None)
        if name == "init-admin":
            sp.add_argument("--email", required=True)
            sp.add_argument("--name", default="")
        if name in ("person-export", "person-erase"):
            sp.add_argument("--email", required=True)
        if name == "set-tenant-password":
            sp.add_argument("--customer", required=True, help="the customer's short name (slug)")
        if name == "rotate-key":
            sp.add_argument("--new-key-file", default=None)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
