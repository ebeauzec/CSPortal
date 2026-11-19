"""Module registry. Each module file defines MODULE (the manifest) and register(app)."""
from __future__ import annotations

import importlib
import logging

log = logging.getLogger("csportal")

ORDER = ["core_accounts", "tenant_dashboard", "system", "catalogue", "tenant_onboarding", "tenant_access", "s3_access",
         "buckets", "usage_billing", "capacity_alerts", "audit_reports"]


def load_all(app) -> None:
    for name in ORDER:
        mod = importlib.import_module(f"{__name__}.{name}")
        app.register_module(mod.MODULE)
    for mid, m in app.modules.items():            # dependency check
        for r in m.get("requires", []):
            if r not in app.modules:
                raise SystemExit(f"Module {mid} needs {r}, which is not installed.")
    for name in ORDER:
        importlib.import_module(f"{__name__}.{name}").register(app)
    log.info("modules loaded: %s", ", ".join(sorted(app.modules)))
