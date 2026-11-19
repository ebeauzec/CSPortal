"""Build the application from a configuration: database, keys, audit, auth, back end, modules, jobs."""
from __future__ import annotations

import logging
import os

from . import crypto, logs, services
from .audit import Audit
from .auth import Auth
from .backends.sim import Simulator
from .config import Config
from .db import Database
from .web.core import App

log = logging.getLogger("csportal")


def build_backend(cfg: Config, app_ref: dict):
    bt = cfg.d["backend"]["type"]
    if bt == "simulator":
        return Simulator(cfg.data_dir / "sim_state.json", seed=7)
    from .backends.storagegrid import StorageGridBackend
    sg = cfg.d["backend"]["storagegrid"]
    return StorageGridBackend(
        sg["base_url"], sg["api_version"], sg["account_id"], sg["username"],
        lambda: os.environ.get(sg["password_env"], ""), sg["ca_file"], sg["verify_tls"], sg["s3_endpoint"],
        get_creds=lambda ref: services.grid_creds_getter(app_ref["app"])(ref),
        put_creds=lambda ref, c: services.grid_creds_putter(app_ref["app"])(ref, c))


def build_app(cfg: Config, seed_demo: bool = True) -> App:
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    log_dir = logs.setup(cfg)
    db = Database(cfg.data_dir / "csportal.db")
    box = crypto.SecretBox(crypto.load_master_key(cfg))
    audit = Audit(db)
    auth = Auth(cfg, db, box, audit)
    ref: dict = {}
    backend = build_backend(cfg, ref)
    app = App(cfg, db, audit, auth, box, backend)
    ref["app"] = app
    app.log_dir = log_dir
    from . import modules
    modules.load_all(app)
    if cfg.demo and seed_demo and db.one("SELECT COUNT(*) FROM plans")[0] == 0:
        from . import demo
        demo.seed(app)
        log.info("demo data created")
    if not backend.verified and cfg.d["backend"]["type"] == "storagegrid":
        logs.event(log, logging.WARNING, "StorageGRID connector is not yet verified on a real grid; run 'conformance' first")
    audit.record("system.start", "system", "system", None, "", f"version mode={cfg.d['mode']} backend={backend.name}")
    return app
