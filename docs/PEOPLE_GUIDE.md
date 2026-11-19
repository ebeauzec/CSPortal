# Guide: invite and manage people (for customer administrators)

This guide is written for the customer's own administrators. The CSP may copy it into its own help pages. The same
steps are shown inside the portal, on the **People** page and on the pages that follow. To give an application access to
storage, see [ACCESS_KEYS_GUIDE.md](ACCESS_KEYS_GUIDE.md): people sign in to this portal, applications use access keys.

## What a person and a role are

A **person** has their own sign-in to this portal. A **role** decides what they can see and change. Give each person the
smallest role that lets them do their work.

| Role | What the person can do |
|---|---|
| **Read only** | View buckets, their access rules, access key IDs, usage and activity. Cannot change anything |
| **Billing** | Usage, statements, alerts and quota requests. Cannot see or change buckets or access |
| **Operator** | Buckets and their settings (versioning, lifecycle, Object Lock, CORS) and access keys. Cannot change who has access, people, storage users or groups, and cannot delete buckets |
| **Administrator** | Everything: people and roles, storage users and groups, who can use each bucket, buckets, access keys, usage, invoices and alerts. Give this to as few people as possible |

## Before you start

- You need the role **administrator**.
- Know the person's **name**, the **e-mail address** they read every day, and **which role** they need. If unsure, choose
  *Read only*.
- The person needs access to that mailbox. The invitation link is sent there.

## Invite a person: step by step

1. Open **People (portal)** in the left menu. Read the five-step summary at the top, then press **Invite a person**.
2. **Question 1: Who are you inviting?** Type the name and the e-mail address. The address is checked for a plausible
   shape; if it looks wrong the page says so and keeps what you typed.
3. **Question 2: What may they do?** Choose one role. *Read only* is selected for you. Each option shows what the role can do.
4. **Question 3: What happens next.** This is a summary, with nothing to choose. Press **Send invitation**.
   Nothing is created until you press the button.

If the address already has an account on this portal, the page says so in plain words and nothing is created.

## What happens after you press Send invitation

The next page shows who was invited, which role, and until when the link is valid. Then:

5. **The person opens the e-mail** and presses the link. The link works **once** and for **72 hours**. Ask them to check
   the spam folder if it is not in the inbox.
6. **They choose a password.** The portal tells them what a good password needs. You never see or set it.
7. **They set up the second sign-in step** (when your provider requires it): they scan a code with an authenticator app on
   their phone and enter the 6 digits it shows.
8. **They sign in.** Back on the **People** page, the status changes from *Waiting for them to accept* to *Active*.

## Manage a person

On the People page press **Manage** next to the person. The page shows their status and offers only the actions that
make sense for them.

| I want to | Press | What happens |
|---|---|---|
| Change what they can do | Choose the new role, then **Change role** | They are signed out at once. The new role applies when they sign in again. The portal asks for your password |
| Send the link again | **Send new invite** | A fresh link is e-mailed. The earlier link stops working |
| Cancel an invitation | **Cancel the link** | The link stops working. The person stays on the list without a way to sign in until you send a new invite |
| Unlock an account | **Unlock** | Clears the block that follows too many wrong passwords |
| End a person's sessions (lost laptop, worry about an account) | **Sign out everywhere** | Every session of that person ends. They can sign in again |
| Help someone who lost their phone | **Reset multi-factor authentication** | They set up the second sign-in step again at the next sign-in. The portal asks for your password |
| Remove someone who has left | **Remove** | They lose access at once. Their name stays in the activity log. The portal asks for your password |

## If something does not work

| You see | What it usually means | What to do |
|---|---|---|
| The person says the e-mail did not arrive | Spam folder, a typo in the address, or the e-mail system is slow | Check spam and the address. Wait a few minutes, then **Send new invite** |
| *This link is not valid or has expired* | The link works once and for 72 hours, or a newer invitation replaced it | **Send new invite** |
| The address was typed wrongly | The invitation went to someone else or nowhere | **Cancel the link**, **Remove** the person, invite again with the right address |
| The page says e-mail is not set up, or could not be sent | Your provider has not configured outgoing e-mail, or the mail system refused it | Ask your provider (they can send a test message from the admin console, Mail outbox). Then press **Send new invite** |
| The person cannot sign in | Several wrong passwords lock the account for a short while | **Unlock** |
| The person lost their phone | They cannot give the second sign-in code | **Reset multi-factor authentication** |

## Things the portal will not let you do

- **Change or remove yourself.** Ask another administrator. Use *Account* to change your own password or authenticator.
- **Demote or remove the last active administrator.** Invite or promote another administrator first.
- **Act on another customer's people.** Every action is limited to your own account.

## Good habits

- Give the smallest role that works. Most people need *Read only*, *Billing* or *Operator*.
- Keep at least two administrators, so one can help the other.
- Remove people on the day they leave. Then review the **Access keys** page: a person who knew an access secret is a reason to
  replace that key ([ACCESS_KEYS_GUIDE.md](ACCESS_KEYS_GUIDE.md)).
- Use **Sign out everywhere** if a device is lost.

Everything you do here is recorded on the **Activity** page (`user.create`, `user.reinvite`, `user.invite_revoked`,
`user.role_change`, `user.sessions_ended`, `user.unlocked`, `user.mfa_disabled`, `user.remove`).
