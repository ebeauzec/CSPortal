# Guide: create an access key (for customer administrators)

This guide is written for the customer's own administrators. The CSP may copy it into its own help pages. The same
steps are shown inside the portal, on the **Access keys** page and on the pages that follow.

## What an access key is

An access key is a pair of codes. Your application, backup tool or script uses them to sign in to your storage, in the
same way a person uses a user name and a password.

| Part | What it is | Secret? |
|---|---|---|
| **Access key ID** | Starts with letters and numbers, for example `AKE1CD962EEE594818CD`. Says *which* key this is | No. It is shown in the list |
| **Secret access key** | A long random text. Proves the key is yours | **Yes.** Shown **once**, when you create the key. The portal does not keep it |

Each key has its own permissions. Give every application its own key, so you can change or remove one without
touching the others.

## Before you start

- You need the role **administrator**. An **operator** can add a replacement key to an existing key but cannot create
  a new key with new permissions.
- Know **what will use the key** (for example "the nightly backup") and **which buckets** it needs.
- Have a safe place ready for the secret: a password manager, or your application's secret store.

## Create a key: step by step

1. Open **Access keys** in the left menu. Read the five-step summary at the top, then press **Create an access key**.
2. **Question 1: What is this key for?**
   Type a short name, for example `nightly-backup`. Use letters, numbers, dot, hyphen and underscore (2 to 26
   characters). The name appears in the list of keys. You may add a note, for example "the backup server in the office".
3. **Question 2: What may it do?**
   - **Read only**: download and list objects. It cannot change or delete anything. Choose this if you are not sure.
   - **Read and write**: also upload, replace and delete objects.
4. **Question 3: Which buckets?**
   - **Only the buckets I tick**: the key cannot see your other buckets. This is the safest choice.
   - **All buckets**: the key works on every bucket, including buckets you create later.
5. **Question 4: How long should it work?**
   Choose 30 days, 90 days (the suggestion), 180 days, 1 year or never. When the day arrives the key stops working
   by itself. A short life limits the damage if a key is ever lost.
6. Press **Create access key**. If something is missing the page tells you in plain words and keeps what you typed.
   Nothing has been created until you press the button.

## Save the secret

The next page shows the **Access key ID** and the **Secret access key**.

7. Press **Copy** next to each code and put them in your safe place. **This is the only time the secret is shown.**
   If you lose it, you cannot see it again: create a new key and delete the old one.
8. Press **I have saved the secret** when you are done.

## Connect your application

The page also shows everything the application needs. Almost every tool asks for the same four things:

| Setting | Where to find it |
|---|---|
| Endpoint (service URL) | Shown on the page, for example `https://s3.example.net` |
| Region | Shown on the page, for example `us-east-1` |
| Access key ID | Shown on the page and in the list of keys |
| Secret access key | Shown once, on the page after creation |

9. Open the storage settings of your application. Look for "S3", "object storage", "S3-compatible" or "custom endpoint".
10. Enter the four values. If the tool asks for an addressing style, choose **path-style**.

## Test that it works

11. With the AWS command line installed, paste the four lines the page gives you into a terminal:
    ```
    export AWS_ACCESS_KEY_ID=...        (your key ID)
    export AWS_SECRET_ACCESS_KEY=...    (your secret)
    export AWS_DEFAULT_REGION=...       (your region)
    aws s3 ls --endpoint-url https://s3.example.net
    ```
    On Windows PowerShell use `$env:AWS_ACCESS_KEY_ID="..."` for the first three lines.
    A list of buckets (or an empty list) means the key works. A key limited to some buckets lists only those; address a bucket
    directly with `aws s3 ls s3://bucket-name --endpoint-url ...`.
12. Back in the portal, open **Access keys**: the key is listed with what it can do, which buckets, and the day it expires.
    **Last used** fills in after the first request.

## If something does not work

| You see | What it usually means | What to do |
|---|---|---|
| `AccessDenied` or 403 | The key may not use that bucket, or it is read only and you tried to write | On **Access keys** press **Change permissions**: tick the bucket, or choose Read and write |
| `SignatureDoesNotMatch` | The secret was copied with a missing or extra character, or the computer's clock is wrong | Copy the secret again; if you lost it, create a new key |
| `InvalidAccessKeyId` | The ID is mistyped, or the key was deleted or has expired | Check the list on **Access keys**; create a new key if needed |
| Timeout, cannot connect, certificate error | Wrong endpoint, or the network blocks it | Use the endpoint exactly as shown; ask your network team to allow it |
| `NoSuchBucket` | The bucket name is mistyped | Check the name on **Buckets** |

## Change what a key may do

Open **Access keys** and press **Change permissions** on the key. Change Read only or Read and write, or the list of
buckets, and save. The change applies to that key only. For finer rules on one bucket (a single folder, a network
address) use the bucket's **Manage access** page ([CUSTOMER_CONTROLS.md](CUSTOMER_CONTROLS.md)).

## Replace a key without any downtime

Do this before the expiry date, and whenever a person who knew the secret leaves.

1. On **Access keys**, find the key. Under its table choose how long the new key should be valid and press **Add key**.
2. Copy the new secret (shown once) and enter it in your application.
3. Check the application works with the new key.
4. Delete the old key (**Delete** in its row; the portal asks you to confirm and to enter your password again if you
   have not done so recently).

A name can hold up to 5 keys, so the old and the new key work side by side while you switch.

## Remove a key for good

Press **Delete** on the key. Applications using it stop working at once. If it was the only key of that name, its
permissions are removed too, so nothing is left behind.

## Good habits

- One key per application. Never share one key between teams.
- Prefer **Read only** and **Only the buckets I tick** unless the application really needs more.
- Never put a secret in source code, e-mail or a chat. Use a password manager or secret store.
- Keep the 90-day expiry and replace keys on a schedule.
- If a secret may have leaked, delete the key at once and create a new one.

Everything you do here is recorded on the **Activity** page (`key.create`, `key.delete`).
