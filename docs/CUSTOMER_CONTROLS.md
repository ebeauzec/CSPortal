# Customer controls

This page lists everything a customer administrator can do in the portal, which role may do it, what the portal
checks, and what is written to the activity log. It is the reference for the CSP's support staff and for
anyone testing the portal against a real grid.

**Status.** Every control below is built and tested against the simulator. The bucket settings are also tested
against a fake grid that speaks TLS and checks S3 signatures (`tests/test_access.py`). **None of it is verified on a
real StorageGRID yet.** The test plan for that is in [STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md#test-plan-for-a-real-grid).

## Roles

| Role | Can do |
|---|---|
| administrator | Everything below |
| operator | Buckets and their settings (create, versioning, lifecycle, Object Lock, CORS) and access keys. Cannot change who has access, people, storage users or groups. Cannot delete buckets |
| billing | Usage, statements, alerts, quota requests |
| read-only | View buckets, their access rules, access key IDs, usage, activity |

The CSP can switch whole modules off per customer and per plan; a switched-off module is hidden and refused.

## Password confirmation for sensitive actions

These actions ask for the password again (and the authenticator code when multi-factor is on) if the last
confirmation is older than the CSP's setting (default 10 minutes): change a role, remove a person, reset a person's
multi-factor, delete a group, storage user, access key or bucket, change public access or the policy of a bucket, set
Object Lock. Nothing changes until the person confirms; the form is then carried out once. Confirmation is recorded
as `user.reauth`.

## 1. People (portal users)

Page: **People (portal)**. Permission to change: `access.edit` (administrator).

| Invite a person (guided) | One page, three questions: who (name, e-mail), what they may do (one role, *Read only* preselected, each with a plain description), and what happens next. Problems are explained in plain words and the typed answers are kept. The result page shows the role and link expiry, whether the e-mail was sent, what the person will do, and a troubleshooting table. The link works **once** and for **72 hours**. Steps for customers: [PEOPLE_GUIDE.md](PEOPLE_GUIDE.md) |
| People list | Status in words (*Active*, *Waiting for them to accept (link valid until ...)*, *Link expired*, *No active link*, *locked*), last sign-in, MFA, a five-step summary and a **Manage** link per person |
| Manage a person | One page per person (`/team/person`) that shows only the actions that apply: change role (radio list with consequences), send a new invitation, cancel the link, unlock, sign out everywhere, reset MFA, remove. Nothing on it for yourself, or for a viewer without `access.edit` |
| Send a new invitation | Cancels every earlier unused link for that person, then sends a new one |
| Revoke an invitation | Cancels the link. The person stays on the list, marked *No active link*, and cannot sign in until invited again |
| Change a role | Per person. The person is **signed out** and the new role applies at the next sign-in. Asks for the password again |
| Sign out everywhere | Ends every session of that person |
| Unlock | Clears the lock-out after too many wrong passwords |
| Reset MFA | The person sets up multi-factor authentication again at the next sign-in. Asks for the password again |
| Remove | Deletes the person and their sessions and invitations. Asks for the password again |

Guards: nobody can change or remove their own entry; the last active administrator cannot be demoted or removed;
a person is looked up by customer, so an administrator can never act on another customer's people.

Audit actions: `user.create`, `user.reinvite`, `user.invite_revoked`, `user.role_change` (old -> new),
`user.sessions_ended`, `user.unlocked`, `user.mfa_disabled`, `user.remove`.

## 2. Storage users and groups

Page: **Storage users**. Permission to change: `access.edit`.

A **group** says what its members may do and on which buckets. A **storage user** belongs to groups and holds S3
access keys; applications sign in with those keys. Storage users have no password and no portal sign-in.

| Control | Behaviour |
|---|---|
| Create group | Read only or read and write; for every bucket, or limited to the buckets you tick |
| Change group | Change access and the bucket list later. Removing every tick means **all** buckets, including buckets created later (the page says so) |
| Stale buckets | A bucket that was deleted stays in a group's list, shown as "gone", until you untick it. If a bucket with the same name is created again the group gets access to it again |
| Delete group | Refused while the group still has members |
| Create storage user | Name, description, first group |
| Change groups of a user | Tick any number of groups |
| Disable / enable / delete a user | Disabled users cannot create keys |

How the group policy is written to the grid: *read only* allows `GetObject`, `GetObjectVersion`, `ListBucket`,
`GetBucketLocation` (plus `ListAllMyBuckets` when the group covers every bucket); *read and write* allows `s3:*`.
A group limited to named buckets gets only those buckets and their objects as resources, and is **not** allowed to
list the account's other buckets. Some S3 clients need to list buckets; address the bucket directly for those.

Audit actions: `group.create`, `group.update`, `group.delete`, `storage_user.create`, `storage_user.groups`,
`storage_user.disable`, `storage_user.enable`, `storage_user.delete`.

## 3. Access keys

Page: **Access keys**. Permission to change: `keys.manage` (administrator, operator).

- **Guided creation** (administrator): the page *Create an access key* asks four questions (what is it for, read only
  or read and write, which buckets, how long). The portal then creates the storage user and its own group
  (`key-<name>`) and the key in one step, and leaves nothing behind if the grid refuses part of it. The result page
  shows the secret once, the four connection settings, a test command and a troubleshooting table. The steps for the
  customer are in [ACCESS_KEYS_GUIDE.md](ACCESS_KEYS_GUIDE.md).
- *Change permissions* on a key opens its group, so access and buckets can be changed later. Deleting the last key of
  a guided key also removes its user and group (`key.remove_all`).
- Operators (`keys.manage` without `access.edit`) can add a replacement key to an existing key but cannot create new
  permissions.
- Up to 5 keys per storage user. The secret is shown **once**; the portal never stores it.
- Optional **expiry**: 30, 90 (suggested), 180 days, 1 year or never. The page shows the date and the days left, and marks keys
  that are expired or expire within 14 days. The grid enforces the expiry.
- To rotate: create a new key, switch the application, delete the old key.
- Audit: `key.create` (with access, buckets and expiry), `key.delete`, `key.remove_all`.

## 4. Who can use a bucket (access policy)

Page: bucket > **Manage access**. Permission to change: `access.edit` (administrator). Operators and read-only users
can view the rules.

The page shows the bucket policy as readable rules, and offers four ways to change it.

1. **Guided grant.** Pick *everyone in this storage account*, a group or a storage user; pick a level; optionally
   a folder (key prefix).

   | Level | Allows |
   |---|---|
   | Read | Get objects and versions, list the bucket, find its region |
   | Read and write | Read, plus put, delete (including versions) and manage multipart uploads |
   | Upload only | Put objects and manage multipart uploads. Cannot read or list |

   With a folder, object actions apply to that prefix only and listing is limited to it by a condition.
2. **Make public / private.** Public means everyone can read every object. Only if the plan allows public buckets.
   The button asks for confirmation. Public access is read-only; the editor refuses public write.
3. **Require encrypted connections.** Adds a deny rule for any request that does not use HTTPS.
4. **Free editor.** The policy as JSON, checked before it is saved. The text you typed is kept when there are errors.

Statements made by the portal carry an ID starting `csportal`, so the portal can show, change and remove them as
one unit. Statements written by hand, or by an S3 tool, are shown as "Custom statement" and are kept exactly as they
are; they can be removed one at a time (the page checks the ID so a stale click cannot remove the wrong one).

### What the policy checker enforces

| Rule | Why |
|---|---|
| Resources must be this bucket or objects in it (`arn:aws:s3:::name` or `arn:aws:s3:::name/...`); `name-evil/*` is refused | A policy cannot reach another bucket |
| Principals must be this storage account's root, users or groups, or `*` | One customer cannot hand access to another account from the portal |
| `*` (public) is refused unless the plan allows public buckets, and then only for `GetObject`, `GetObjectVersion`, `ListBucket`, `GetBucketLocation` | No accidental public write; plan limits are respected |
| `NotPrincipal`, `NotAction`, `NotResource` are refused | They are easy to get wrong and hard to review |
| Actions must be `s3:...` names | No other service's actions |
| Conditions only with `aws:SecureTransport`, `aws:SourceIp`, `s3:prefix`, `s3:delimiter`, `s3:max-keys`, and at most 4 operators | Keeps the policy reviewable |
| At most 50 statements and 20 KiB | Limits of the storage service |
| Unknown fields, duplicate IDs, bad IDs | Mistakes caught before the grid sees them |

The grid applies its own rules as well. The portal check does not replace them; it makes the common mistakes
impossible and gives clear messages.

Audit actions: `bucket.access_grant`, `bucket.access_revoke`, `bucket.public`, `bucket.private`,
`bucket.require_tls`, `bucket.allow_plain`, `bucket.policy_set`.

## 5. Bucket settings

Permission to change: `buckets.edit` (administrator, operator). Deleting a bucket needs `buckets.delete` (administrator).

| Setting | Behaviour |
|---|---|
| Create (guided) | One page, four questions: name and region; protection (keep old versions, latest only, or lock with a retention time and standard or strict mode; locking only if the plan allows); optional clean-up (incomplete uploads after 7 days, automatic expiry, old-version expiry); who can use it (private). Names are checked in plain words with a suggested fix; the plan's bucket limit is checked; if the grid refuses part of the set-up the empty bucket is removed again. The result page lists next steps, including creating an access key for the bucket. Steps for customers: [BUCKETS_GUIDE.md](BUCKETS_GUIDE.md) |
| Versioning | Turn on, suspend. Cannot be suspended on a bucket with Object Lock |
| Lifecycle | Rules: expire objects, delete old versions, clean incomplete uploads, with an optional prefix. Rules the portal cannot describe (tags, transitions) are shown as "custom rule" and **kept unchanged** when you change another rule |
| Object Lock default retention | Governance or compliance, for 1 to 36500 days or 1 to 100 years. Compliance needs a tick that it cannot be shortened or removed. Applies to objects written afterwards. Only on buckets created with Object Lock |
| CORS | Rules with allowed origins (`https://host`, `https://*.host`, or `*`), methods (GET, PUT, POST, DELETE, HEAD), request headers, cache age. Up to 20 rules |
| Delete | Only an empty bucket |

If a setting cannot be read from the grid, the bucket page says which one instead of showing an empty value.

Audit actions: `bucket.create` (with protection and clean-up), `bucket.versioning`, `bucket.lifecycle_add`, `bucket.lifecycle_remove`,
`bucket.lock_default`, `bucket.lock_default_clear`, `bucket.cors_add`, `bucket.cors_remove`, `bucket.delete`.

## Not built

| Capability | Note |
|---|---|
| Legal hold and per-object retention | Set per object by applications with the S3 API |
| Object browser (upload, download, delete in the browser) | Planned for Release 2 |
| Default bucket encryption | Planned; depends on what the supported releases offer |
| Object ACLs | Not offered; use bucket policies |
| Cross-account sharing | Refused by the policy checker; the CSP can arrange it |
| Platform services (replication, notifications) and own identity source | Planned for Release 2 |
| Approval by a second administrator for dangerous customer actions | Planned |
| Webhook alert channel | Planned |

## Using the controls against a real grid

Before real customers use these controls, run the test plan in
[STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md#test-plan-for-a-real-grid) on a non-production grid and
record the result in the changelog. The points most likely to differ between releases are the group policy
format, the bucket policy principals, S3 settings calls on the tenant's service key, and access key expiry.
