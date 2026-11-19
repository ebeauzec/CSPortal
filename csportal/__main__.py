"""Command line: python -m csportal <command>

  serve        run both surfaces and the job runner
  demo         run in demo mode (simulated storage, sample data) in a separate data folder
  genkey       print a new master key
  init-admin   create the first provider administrator and print the set-password link
  selftest     run the built-in checks and exit
  conformance  compare the StorageGRID connector's calls with the grid's own API description
  bundle       write a diagnostic bundle to a file
  backup       write a database backup
  verify-audit check the audit hash chain
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
    dest = Path(args.out) if args.out else cfg.data_dir / "backups" / f"csportal-{time.strftime('%Y%m%dT%H%M%S')}.db"
    app.db.backup(dest)
    print(f"Wrote {dest}")


def cmd_verify_audit(args):
    cfg, app = _build(args)
    ok, bad, n = app.audit.verify()
    print(f"audit chain: {'intact' if ok else 'BROKEN at record ' + str(bad)} ({n} records)")
    sys.exit(0 if ok else 2)


def main(argv=None):
    p = argparse.ArgumentParser(prog="csportal", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default=None, help="path to the JSON configuration file")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in [("serve", cmd_serve), ("demo", cmd_serve), ("genkey", cmd_genkey), ("init-admin", cmd_init_admin),
                     ("conformance", cmd_conformance), ("bundle", cmd_bundle), ("backup", cmd_backup), ("verify-audit", cmd_verify_audit)]:
        sp = sub.add_parser(name)
        sp.set_defaults(fn=fn, demo=(name == "demo"))
        sp.add_argument("--port", type=int, default=None)
        sp.add_argument("--data-dir", default=None)
        sp.add_argument("--out", default=None)
        if name == "init-admin":
            sp.add_argument("--email", required=True)
            sp.add_argument("--name", default="")
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
