# Verify the connector on a real grid

**Use it when** the portal talks to a real StorageGRID for the first time, after a grid upgrade, and after a portal
release that changes the connector. Until a run of this page is recorded for your grid release, the connector is
**unverified** and the portal says so on the System page.

**You need:** a **non-production** grid (or a throw-away tenant on a grid you can accept risk on), the grid
administrators for the steps that use Grid Manager, an S3 client (for example the AWS CLI), and a place to record
results.

## Steps

1. Complete [FIRST_START.md](FIRST_START.md) up to the connector check.
2. Run the 17-step table in [STORAGEGRID_INTEGRATION.md](../STORAGEGRID_INTEGRATION.md#test-plan-for-a-real-grid) in order.
   Use a throw-away customer and bucket names that cannot clash with real data.
3. After each step write: the step number, the grid release and API version, pass or fail, and for a failure the
   request id shown on the error page (it finds one line in the log) and the diagnostic bundle ([DIAGNOSTICS.md](DIAGNOSTICS.md)).
4. Pay special attention to the five points most likely to differ between releases, and write down what the grid
   actually did:
   - the tenant root sign-in and the S3 key of `csportal-service` (steps 3 and 5 to 12);
   - the group policy format (step 7 and 8);
   - bucket policy principals (step 9);
   - Object Lock default retention (step 13);
   - access key expiry (step 7).
5. Fix what differs in the connector (`csportal/backends/storagegrid.py`) with a test that reproduces it, and repeat the step.

## Check

Every step passes on the same release. Then, in one commit: add the release to the supported range in
STORAGEGRID_INTEGRATION.md, change "unverified" to "verified on release X" in the README, TENANT_PARITY and
CUSTOMER_CONTROLS, set `verified` in the connector, and add the dated result to the changelog.

## Go back

Delete the throw-away customer (Customers, Close) and its tenant on the grid, and remove its buckets. Run
[DRIFT.md](DRIFT.md) to confirm the portal and the grid agree.
