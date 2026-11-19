# Guide: create a bucket (for customer administrators)

This guide is written for the customer's own administrators. The CSP may copy it into its own help pages. The same
steps are shown inside the portal, on the **Buckets** page and on the pages that follow. The companion guide for
giving an application access is [ACCESS_KEYS_GUIDE.md](ACCESS_KEYS_GUIDE.md).

## What a bucket is

A bucket is a top-level folder that holds your files. In storage language the files are called **objects**. Everything you
store lives in a bucket. Most customers use one bucket for each purpose: for example one for backups, one for website
images, one for log files.

## Before you start

- You need the role **administrator** or **operator**.
- Choose a **name**. It must be unique across the whole service, so include your company or project name, for
  example `acme-backups-2026`. **The name cannot be changed later.**
- Decide how long the data must be kept, and whether anything must be protected from deletion.
- Your plan sets how many buckets you may have. The Buckets page shows how many you have used.

## Create a bucket: step by step

1. Open **Buckets** in the left menu. Press **Create a bucket**. Read the short summary at the top of the page.
2. **Question 1: Name and place.**
   Type the name: 3 to 63 characters, lowercase letters, numbers, dots and hyphens. It must start and end with a letter
   or number. If the name does not fit the rules the page says why and suggests a name that does. If your service has
   more than one region, choose where the data is stored; the region cannot be changed later.
3. **Question 2: How should the data be protected?** Choose one.
   - **Keep old versions (recommended).** If a file is deleted or overwritten by mistake, you can get the earlier copy back.
   - **Keep only the latest version.** Uses less space. A deleted or overwritten file cannot be recovered.
   - **Lock objects so nobody can delete or change them.** For records that must stay unchanged for a set time (only
     shown as available if your plan includes it). Open *Settings for locking* and choose how long each object is kept
     and how strict the lock is:
     - **Standard**: a user with special permission can still shorten or remove the lock.
     - **Strict**: nobody, not even the provider, can shorten or remove it until the time ends. Tick the box to confirm
       you understand. **Locking cannot be added to a bucket later**, so decide now.
4. **Question 3: Clean-up (optional).**
   - *Remove incomplete uploads after 7 days* is ticked by default. It frees space left by uploads that never finished.
   - *Delete objects automatically after (days)*: leave empty to keep objects until you delete them. It cannot be combined with locking.
   - *Delete old versions after (days)*: only for buckets that keep old versions. Leave empty to keep them.
5. **Question 4: Who can use it?** Nothing to choose here. A new bucket is **private**: only you can use it, until you
   create an access key or change its access rules.
6. Press **Create bucket**. If something is wrong, the page says what in plain words and keeps your answers.
   Nothing is created until the button is pressed, and if the grid refuses part of the set-up the bucket is removed again.

## After the bucket is created

The next page confirms what was created and lists the next steps:

7. **Give an application access.** Press **Create an access key for this bucket**. The access-key page opens with this
   bucket already ticked. Follow [ACCESS_KEYS_GUIDE.md](ACCESS_KEYS_GUIDE.md).
8. **Test it.** With the key, upload a small file using the AWS command line:
   `aws s3 cp hello.txt s3://<bucket-name>/ --endpoint-url <your endpoint>`
9. **Check the protection.** Open the bucket. The Protection panel shows versioning, locking, privacy and clean-up
   rules with a note on anything to review.
10. **Optional:** share the bucket with a website or limit access to one folder under **Manage access**.

## Good to know

| Question | Answer |
|---|---|
| Can I rename a bucket? | No. Create a new bucket and copy the data across |
| Can I change protection later? | Versioning and clean-up rules, yes. Locking only at creation |
| Can anyone else see my data? | Not until you change the bucket's access rules |
| How do I delete a bucket? | Empty it first, then use **Delete bucket** on its page (administrators only; it asks for your password) |
| I get "name already used" | Bucket names are shared by all customers of the service. Add your company or project name |

## Good habits

- One bucket per purpose, named so the purpose is clear.
- Keep versions on unless you are sure you never need to recover a file.
- Use locking only for records that really must not change. Strict locking is permanent for its period.
- Give each application its own access key, limited to the buckets it needs.

Everything you do here is recorded on the **Activity** page (`bucket.create`).
