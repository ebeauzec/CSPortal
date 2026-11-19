# Architecture

Status: proposed design. Nothing is built yet. Open choices are listed in
[DECISIONS.md](DECISIONS.md).

## Purpose and principles

CSPortal is a **white-label provisioning and self-management portal for a StorageGRID offering**.
The CSP sells object storage under its own brand; the end customer (the tenant) signs in to the
CSP's portal and does everything they would normally do to manage their own tenant, to the maximum
extent StorageGRID allows. The CSP never needs to give a customer access to the Grid Manager or
the native Tenant Manager. [TENANT_PARITY.md](TENANT_PARITY.md) lists every tenant capability and
where it lives in the portal.

Four principles decide every design choice. When two choices compete, the earlier principle wins.

1. **Secure by design.** Least privilege everywhere, deny by default, no standing secrets in clear
   text, the admin console unreachable from the internet, every change audited. Details in
   [SECURITY.md](SECURITY.md).
2. **Simple.** Few moving parts, few dependencies, one way to do each thing. A CSP engineer can
   understand the whole system, run it and recover it. No message broker, no service mesh, no
   microservices. If a feature needs a new kind of component, the feature waits.
3. **Self-contained.** One deployable unit that runs without any outside service: no CDN, no
   third-party scripts, fonts or analytics, no cloud dependency, no call-home. It must work in a
   dark site. Outside services (mail relay, identity provider, billing export) are optional and
   configured by the CSP.
4. **Maximum tenant self-service.** If StorageGRID lets a tenant do it, the portal lets the tenant
   do it, within limits the CSP sets per plan. The CSP controls what is *allowed*; the customer
   controls what is *done*.

## Goals

1. **Two surfaces, one product.** An externally facing **customer portal** and an internally
   facing **admin console** where all configuration of the portal happens.
2. **Modular.** Every capability (onboarding, metering, buckets, alerts, and so on) is a module that
   the CSP can switch on or off, per plan and per customer, without a code change.
3. **StorageGRID behind a connector.** The portal talks to a storage back end through one
   connector interface. StorageGRID is the first connector; others stay possible.
4. **Safe by construction.** Customers never receive grid-level credentials. The admin console is
   not reachable from the internet.
5. **Operable.** Every failure leaves enough information to diagnose it remotely (see
   [OPERATIONS.md](OPERATIONS.md)).

## Overview

```
   Internet                       CSP private network
 ┌──────────┐                ┌─────────────────────────────────────────────┐
 │ Customer │  HTTPS         │  Customer-portal  ┐                         │
 │ browser  │ ─────────────► │  surface (public) │                         │
 └──────────┘                │                   ├─► Core ─► Module ─►     │
 ┌──────────┐  HTTPS (VPN /  │  Admin-console    │   (auth,   runtime      │
 │ CSP staff│  private only) │  surface (private)┘    RBAC,    (modules)    │
 └──────────┘ ─────────────► │                        audit,               │
                             │                        settings)            │
                             │            │                   │            │
                             │       Portal database     Connector layer   │
                             │      (accounts, plans,          │           │
                             │       usage, audit)             ▼           │
                             │                      StorageGRID Grid Mgmt  │
                             │                      API, Tenant Mgmt API,  │
                             │                      metrics, S3 endpoints  │
                             └─────────────────────────────────────────────┘
```

## Components

### Core
Small, stable, and the only part every deployment runs.
- **Identity and sessions.** Local accounts with multi-factor authentication; optional external
  identity provider (OIDC or SAML) per surface. Customer users and CSP staff are separate user
  stores with separate sessions.
- **Authorisation.** Role-based access control. Roles belong to a surface: customer roles
  (administrator, operator, billing, read-only) and CSP roles (super administrator, operations,
  finance, support). Every module declares the permissions it needs.
- **Tenancy of the portal.** Every record carries a customer id; the data layer enforces it so a
  module cannot read another customer's data by mistake.
- **Settings.** Layered: product default, CSP, plan, customer. Modules declare a settings schema
  and the admin console renders its screens from that schema.
- **Audit log.** Append-only record of every change and every sign-in, per customer and for the CSP. Hash-chained,
  with signed checkpoints and a retention archive (`audit.py`).
- **Sensitive-action controls.** Routes can require a fresh password confirmation (`reauth`), and the three most
  dangerous provider actions can require a second super administrator (`approvals.py`).
- **Operations.** Backups with integrity checks, drift check against the grid, master-key rotation and personal-data
  export and erasure (`ops.py`), run by the job runner, the admin console and the command line.
- **Job runner.** Scheduled and queued work (metering, alerts, invoices, clean-up).
- **Notifications.** E-mail and webhook channels, templated and per-customer branded.
- **Module registry.** Loads module manifests, checks versions and dependencies, mounts routes.

### Surfaces
- **Customer portal** (public). Serves the customer-facing screens of the enabled modules, with the
  CSP's branding. Rate-limited, hardened, no administrative endpoints.
- **Admin console** (private). Serves the configuration screens of every module plus the core
  screens: customers, plans, catalogue, users, branding, connectors, jobs, audit, system health.
- The two surfaces are separate listeners (own port or host name) from the same code base, so the
  admin console can be bound to a private interface only.

### Modules
A module is a folder with a manifest and up to three parts: a back-end part (routes, jobs, data
migrations), a customer-portal part (screens) and an admin-console part (screens). See
[MODULES.md](MODULES.md) for the manifest, lifecycle and the planned module list.

### Connector layer
One interface, `StorageBackend`, with operations such as `createTenant`, `setQuota`,
`listBuckets`, `getUsage`, `createAccessKey`, `getHealth`. The StorageGRID connector implements it
against the Grid Management API and the Tenant Management API (see
[STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md)). Modules call the interface, never the
StorageGRID API directly, so a module's logic can be tested against a simulated back end.

### Data
One relational database, embedded by default (a single file, no separate database server; a server
database is an option for large deployments, see [DECISIONS.md](DECISIONS.md)). Main tables: customers, plans, plan-module entitlements, portal users,
roles, role assignments, tenant links (customer to grid tenant), usage samples, statements,
quota requests, alert rules, notifications, settings, audit events, jobs. Secrets are not stored
in plain text (see [SECURITY.md](SECURITY.md)).

## Key flows

**Customer created.** Admin console → core creates the customer record from a plan → connector
creates the grid tenant and quota → core stores the link and sends the invitation → customer sets
up sign-in → audit events recorded at each step. If the connector step fails, the customer stays
in a *pending* state with the error and a retry action; nothing is half-created silently.

**Usage statement.** Job runner samples usage per tenant on a schedule → samples stored → month-end
job closes the period using the plan's rate card → statement stored and immutable → customer
downloads it; any later correction is a new, linked adjustment record.

**S3 key created.** Customer portal → core checks the role → connector creates the key on the
tenant's behalf → the secret is shown once, never stored by the portal → audit event.

## Deployment shape

One application image that contains everything: both surfaces, the job runner, all static assets
(vendored, no external fetches) and the embedded database. One process, one data directory, one
configuration file. Backup is a copy of the data directory plus the encryption key (kept apart).
The customer-portal surface sits behind the CSP's reverse proxy and web application firewall; the
admin console is published on a private network only. Single node first: on Kubernetes that means exactly one replica
with a ReadWriteOnce volume (see [../deploy/kubernetes/README.md](../deploy/kubernetes/README.md)). The data layer keeps no
state outside the database, so a later move to a server database and several replicas stays possible.

## Non-goals (for now)

- Replacing the StorageGRID Grid Manager for grid administration (node, ILM and hardware work stay there).
- Being a general billing system. CSPortal produces statements and exports; the CSP's finance
  system keeps invoicing and payment.
- Serving the S3 data path. Customers talk to the S3 endpoints directly; the portal is control plane only.
