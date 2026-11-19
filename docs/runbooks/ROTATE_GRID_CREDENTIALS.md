# Rotate grid credentials

**Use it when** the grid administrators change the portal's grid password on a schedule, a person who knew it
leaves, or the master key may have leaked.

The portal holds two kinds of grid credentials:

| Credential | Where it is stored | How it is changed |
|---|---|---|
| **Grid provisioning password** (the portal's user in the grid account, used for tenant accounts and usage) | Encrypted in the console, or in the environment variable `CSPORTAL_GRID_PASSWORD` | Part 1 below |
| **Tenant root password** (one per customer, used for that customer's groups, users and access keys) | Encrypted in the database | Part 2 below |

## Part 1: the grid provisioning password

**You need:** a staff user with `settings.edit` (a second super administrator if `security.four_eyes` is on).

1. In Grid Manager, change the password of the portal's grid user. From now until step 3 the portal cannot reach the grid.
2. In the portal, open **Storage grid**. Enter the new password in the password field, press **Test these settings first**.
3. Press **Save and apply**. If four-eyes is on, a different super administrator approves it on the **Approvals** page.
4. If the password comes from the environment variable instead, change the variable in the secret store and restart.

Check: System health shows the grid reachable; the next usage-sample job succeeds.
Go back: enter the previous password (if you still have it) and save.

## Part 2: a tenant root password

**You need:** the customer's short name (slug, shown on the customer page) and a grid administrator.

1. In Grid Manager, Tenants, choose the account, **Change root password**. Choose a long random value.
2. Store it in the portal. The command tests it with a real grid call before keeping it. If the grid refuses it, the
   old stored value is kept.
   ```
   docker compose exec -e CSPORTAL_NEW_TENANT_PASSWORD='the-new-password' csportal python -m csportal set-tenant-password --customer riverbend
   ```
   (Without the variable the command asks for the password.)
3. Restart the service, or wait up to an hour, so running sessions pick up the new password.

Check: open the customer's **Storage users** page: the list loads. The audit log has `tenant.credentials_updated`.
Go back: repeat with the previous password if you still have it.

## After a suspected leak

Rotate the master key ([ROTATE_MASTER_KEY.md](ROTATE_MASTER_KEY.md)), then Part 1, then Part 2 for **every** customer,
then ask customers to rotate their own access keys. Record the times in your incident record.
