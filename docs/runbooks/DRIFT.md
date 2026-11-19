# Drift between the portal and the grid

**Use it when** the daily `drift-check` job fails, the Operations page shows differences, or after a restore, a grid
maintenance window or any change made directly on the grid.

**You need:** a staff user with `system.edit` and, for grid-side changes, a grid administrator.

## Run the check

Operations, **Check now**, or `python -m csportal drift` (exit code 2 when there is a difference). The check only
reads. Nothing changes until you press an action button.

## What each line means and what to do

| Report | Meaning | What to do |
|---|---|---|
| **Missing on the grid** | The portal has a customer with a grid reference, but the account is not on the grid | Find out why (deleted by hand? a different grid?). If the account was deleted by mistake, restore it on the grid. If the customer should not exist, close it in the portal. Never create a second account for the same customer without removing the stale reference |
| **Quota differs** | The grid quota is not the quota the portal holds | If the portal value is right, press **Set grid to portal value** (asks for your password). If the grid value was set on purpose, change the customer's plan or quota in the portal so both agree |
| **Not in portal** | A tenant account exists on the grid that the portal does not manage | Informational. It may belong to someone else on a shared grid. Do not touch it from the portal |

## Check

Run the check again: it reports no differences, or only accounts you decided to leave alone. The audit log has
`drift.check` and, for each alignment, `drift.quota_aligned`.

## Go back

A quota alignment can be reversed by setting the old value in the grid or in the customer's plan; the audit entry
holds the value that was written.
