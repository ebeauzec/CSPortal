# Demo mode

Demo mode runs the whole product on a built-in simulated StorageGRID with sample data, so every use case can
be shown without a grid. It is for presentations, evaluation and development.

```
python -m csportal demo                         # customer portal on 8443, admin console on 8444
python -m csportal demo --port 9000 --data-dir ./my-demo
docker run --rm -p 8443:8443 -p 8444:8444 csportal demo --data-dir /tmp/demo
```

Open `http://127.0.0.1:8443/` (customer portal) and `http://127.0.0.1:8444/` (admin console). The sign-in
pages list the sample accounts and their shared demo password.

## Safety rules (enforced in code)

- Demo mode only runs against the simulator. A configuration that asks for demo mode and a real grid is refused.
- It uses its own data directory and its own generated key. It never reads production data.
- A purple banner shows on every page. Mail is captured in the outbox, never sent.
- Multi-factor authentication is optional in demo mode so a demonstration is quick; it can still be turned on.
- All names, addresses and figures are invented. Domains use the reserved `.example` name.

## What is pre-populated

| Item | Content |
|---|---|
| Plans | Starter, Business, Enterprise, each with a rate card, features and a quota |
| Customer: Riverbend Analytics (Business) | 4 buckets (versioned, lifecycle rules, Object Lock backup bucket, one public), storage users and keys, 12 months of daily usage and statements, 4 portal users (administrator, operator, billing, read-only), alerts |
| Customer: Harbourview Media (Starter) | 77% to 87% quota use, no versioning (the protection panel flags it), an alert that has fired, an open quota request |
| Customer: Kestrel Health Group (Enterprise) | Pending: storage account creation failed (simulated). Use **Retry provisioning** in the admin console |
| Provider staff | Super administrator, operations, finance, support |
| Notices | A planned-maintenance notice shown to customers |
| Audit | Activity history for customers and staff |

## Suggested demonstration path

0. **Invitations in the demo.** No mail is delivered. After you invite a person, the result page and the person's Manage page show the
   link, so you can play the part of the invited person. A real portal never shows the link to the person who invites.
1. **UC1 Onboarding.** Admin console: Customers, New customer. The invitation appears under System, Mail outbox
   (demo mode captures mail there); open its link to set a password. Show Kestrel's **Retry provisioning**.
2. **UC3 Buckets.** Sign in as `dana@riverbend.example`. Create a bucket, turn on versioning, add a lifecycle rule, read the
   protection panel. Sign in as Harbourview and try to allow public access: the plan blocks it.
3. **UC1 Access keys.** Create a storage user and an access key; note the secret is shown once.
4. **UC2 Usage and billing.** Usage chart by period, statements, CSV download. In the admin console add an adjustment.
5. **UC4 Capacity.** Harbourview's alert and quota request; approve it in Admin, Quota requests. Raise Riverbend's quota
   request: the Business plan approves it automatically.
6. **Roles.** Sign in as the billing and read-only users to show what each can see and change.
7. **Provider view.** Audit log with chain check, logs, diagnostic bundle, plan and module switches.

**Reset:** System health, Reset demo data (super administrator), or delete the demo data directory.
Simulated usage grows a little every two minutes so charts move during a long demonstration.
