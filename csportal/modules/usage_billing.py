"""UC2: usage, metering and billing visibility (customer) and statement management (admin)."""
from __future__ import annotations

import csv
import io

from .. import services
from ..util import GB, human_bytes, money
from ..web import ui
from ..web.core import Raw, redirect, text_response

MODULE = {"id": "usage-billing", "name": "Usage and billing", "version": "1.0.0", "surfaces": ["customer", "admin"],
          "requires": [], "description": "Usage trends, monthly statements and exports.",
          "nav": [{"surface": "customer", "label": "Usage", "path": "/usage", "perm": "usage.view", "group": "Service", "order": 10},
                  {"surface": "customer", "label": "Statements", "path": "/statements", "perm": "billing.view", "group": "Service", "order": 20},
                  {"surface": "admin", "label": "Statements", "path": "/billing", "perm": "billing.view", "group": "Finance", "order": 10}]}


def _csv(rows, header):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(header)
    for r in rows:
        # guard against spreadsheet formula injection in text cells
        w.writerow([("'" + c) if isinstance(c, str) and c[:1] in "=+-@" else c for c in r])
    return out.getvalue()


def register(app):
    @app.route("customer", "GET", "/usage", perm="usage.view", module="usage-billing")
    def usage(ctx):
        c = ctx.customer
        u = app.backend.usage(c["tenant_ref"])
        days = int(ctx.q("days", "90")) if ctx.q("days", "90") in ("30", "90", "180", "365") else 90
        series = services.usage_series(app, c["id"], days)
        picker = Raw('<form method="get" action="/usage"><label>Period <select name="days" data-autosubmit>' +
                     "".join(f'<option value="{d}"{" selected" if d == days else ""}>{l}</option>'
                             for d, l in [(30, "30 days"), (90, "90 days"), (180, "6 months"), (365, "12 months")]) +
                     "</select></label></form>")
        chart = ui.card("Stored data (GB)", Raw(picker + ui.line_chart(series, "", quota=c["quota_gb"])))
        bars = ui.card("By bucket (GB)", ui.bar_chart(sorted([(b["name"], b["bytes"] / GB) for b in u["buckets"]], key=lambda x: -x[1])[:12]))
        rows = [[b["name"], human_bytes(b["bytes"]), f"{b['objects']:,}"] for b in sorted(u["buckets"], key=lambda b: -b["bytes"])]
        tbl = ui.card("Buckets", ui.table(["Bucket", "Size", "Objects"], rows, "No data yet."))
        mtd = services.month_to_date(app, c)
        est = ui.card("This month so far", Raw(
            f"<p><strong>{money(mtd['amount'], mtd['currency'])}</strong> estimated for the month, based on an average of "
            f"{mtd['avg_gb']:,.1f} GB stored. The final figure is on your monthly statement.</p>")) if ctx.can("billing.view") else ""
        return ui.page(ctx, "Usage", Raw(ui.grid(ui.stat("Stored now", human_bytes(u["bytes_used"])),
                                                 ui.stat("Objects", f"{u['objects']:,}"),
                                                 ui.stat("Quota", human_bytes(c["quota_gb"] * GB)), cols=3) + chart + bars + est + tbl), "/usage")

    @app.route("customer", "GET", "/statements", perm="billing.view", module="usage-billing")
    def statements(ctx):
        sts = ctx.scoped.select("statements", order="period DESC, created_at DESC")
        rows = [[s["period"], f"{s['avg_gb']:,.1f}" if not s["adjusts"] else "-", f"{s['peak_gb']:,.1f}" if not s["adjusts"] else "-",
                 money(s["total"], s["currency"]), ui.badge(s["state"], "" if s["state"] == "closed" else "warn"), s["note"] or "",
                 ui.link(f"/statements/{s['id']}.csv", "CSV") if not s["adjusts"] else ""] for s in sts]
        return ui.page(ctx, "Monthly statements",
                       Raw(ui.card("Statements", ui.table(["Period", "Average GB", "Peak GB", "Amount", "Type", "Note", ""], rows,
                                                           "No statement yet. The first one is created after the end of the month.")) +
                           ui.card("About your statements", Raw("<p class='muted'>Statements are created once a month and do not change. "
                                                                "If a correction is needed, it appears as a separate adjustment line.</p>"))), "/statements")

    @app.route("customer", "GET", "/statements/{sid}.csv", perm="billing.view", module="usage-billing")
    def statement_csv(ctx):
        s = ctx.scoped.one("statements", "id=?", (ctx.params["sid"],))
        if not s:
            return redirect("/statements")
        ctx.audit("statement.export", s["period"])
        return text_response(_csv([[s["period"], s["avg_gb"], s["peak_gb"], s["storage_amount"], s["other_amount"], s["total"], s["currency"]]],
                                  ["period", "average_gb", "peak_gb", "storage_amount", "other_amount", "total", "currency"]),
                             "text/csv; charset=utf-8", filename=f"statement-{s['period']}.csv")

    # ------------------------------------------------------------ admin
    @app.route("admin", "GET", "/billing", perm="billing.view", module="usage-billing")
    def admin_billing(ctx):
        rows = app.db.all("SELECT s.*, c.name cname FROM statements s JOIN customers c ON c.id=s.customer_id ORDER BY s.period DESC, c.name LIMIT 300")
        trs = [[r["period"], r["cname"], f"{r['avg_gb']:,.1f}", money(r["total"], r["currency"]), ui.badge(r["state"], "" if r["state"] == "closed" else "warn"),
                ui.link(f"/billing/{r['id']}", "Adjust") if ctx.can("billing.edit") and not r["adjusts"] else ""] for r in rows]
        close = ""
        if ctx.can("billing.edit"):
            close = ui.card("Close a month", ui.form("/billing/close", [
                {"name": "period", "label": "Month (YYYY-MM)", "value": services.closed_periods_due(app)[0],
                 "attrs": {"pattern": r"\d{4}-\d{2}"}}], ctx.sess.csrf, "Create statements",
                extra=Raw('<p class="muted">Creates a statement for every customer that has usage in that month and none yet. Existing statements are never changed.</p>')))
        return ui.page(ctx, "Statements", Raw(close + ui.card("All statements", ui.table(
            ["Period", "Customer", "Avg GB", "Total", "Type", ""], trs, "No statements yet.",)) +
            ui.card("Export", ui.link("/billing/export.csv", "Download all statements (CSV)", "btn"))), "/billing")

    @app.route("admin", "POST", "/billing/close", perm="billing.edit", module="usage-billing")
    def close(ctx):
        period = ctx.f("period")
        if len(period) != 7 or period[4] != "-" or not (period[:4] + period[5:]).isdigit() or not 1 <= int(period[5:]) <= 12:
            ctx.flash("Error: Enter the month as YYYY-MM.")
            return redirect("/billing")
        n = services.close_period(app, period, ctx.sess.email)
        ctx.flash(f"{n} statement(s) created for {period}.")
        return redirect("/billing")

    @app.route("admin", "GET", "/billing/export.csv", perm="billing.view", module="usage-billing")
    def export(ctx):
        rows = app.db.all("SELECT s.*, c.name cname FROM statements s JOIN customers c ON c.id=s.customer_id ORDER BY s.period, c.name")
        ctx.audit("statement.export_all")
        return text_response(_csv([[r["period"], r["cname"], r["avg_gb"], r["peak_gb"], r["storage_amount"], r["other_amount"], r["total"],
                                    r["currency"], r["state"], r["note"]] for r in rows],
                                  ["period", "customer", "average_gb", "peak_gb", "storage_amount", "other_amount", "total", "currency", "type", "note"]),
                             "text/csv; charset=utf-8", filename="statements.csv")

    @app.route("admin", "GET", "/billing/{sid}", perm="billing.edit", module="usage-billing")
    def adjust_form(ctx):
        s = app.db.one("SELECT s.*, c.name cname FROM statements s JOIN customers c ON c.id=s.customer_id WHERE s.id=?", (ctx.params["sid"],))
        if not s:
            return redirect("/billing")
        return ui.page(ctx, f"Adjust statement {s['period']}", Raw(ui.card(s["cname"], Raw(
            f"<p>Original total: <strong>{money(s['total'], s['currency'])}</strong>. A statement is never edited; an adjustment line is added "
            "(use a negative amount for a credit).</p>" + ui.form(f"/billing/{s['id']}", [
                {"name": "amount", "label": "Adjustment amount", "type": "number", "attrs": {"step": "0.01"}},
                {"name": "note", "label": "Reason (shown to the customer)"}], ctx.sess.csrf, "Add adjustment")))), "/billing")

    @app.route("admin", "POST", "/billing/{sid}", perm="billing.edit", module="usage-billing")
    def adjust(ctx):
        try:
            services.adjust_statement(app, ctx.params["sid"], float(ctx.f("amount")), ctx.f("note"), ctx.sess.email, ctx.req.ip)
            ctx.flash("Adjustment added.")
        except (ValueError, TypeError) as e:
            ctx.flash("Error: " + str(e))
        return redirect("/billing")
