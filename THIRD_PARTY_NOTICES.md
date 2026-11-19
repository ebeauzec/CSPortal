# Third-party notices

CSPortal is proprietary software (see [LICENSE](LICENSE) and [LEGAL.md](LEGAL.md)).
When it includes or depends on open-source components, each is listed below with
its licence. Each component remains under its own licence, which CSPortal's
licence does not change.

## Components

CSPortal uses the Python standard library and one direct third-party package (`cryptography`) with the two
packages it needs. Every dependency change updates this table in the same commit. The CI workflow publishes
a CycloneDX software bill of materials for each build.

| Component | Version | Licence | Source |
|---|---|---|---|
| cryptography (AES-GCM for stored secrets) | 50.0.0 | Apache-2.0 or BSD-3-Clause | https://github.com/pyca/cryptography |
| cffi (needed by cryptography) | 2.1.1 | MIT-0 | https://github.com/python-cffi/cffi |
| pycparser (needed by cffi) | 3.12 | BSD-3-Clause | https://github.com/eliben/pycparser |
| Python runtime and standard library | 3.12 | Python Software Foundation License | https://www.python.org |

The user interface uses no third-party scripts, fonts or images; all assets are written for CSPortal and
served from the application itself.

## Trademarks

* "NetApp" and "StorageGRID" are trademarks of NetApp, Inc. CSPortal is an independent
  product and is not affiliated with, endorsed by or sponsored by NetApp, Inc.
* "S3" and "Amazon S3" are trademarks of Amazon.com, Inc. or its affiliates. CSPortal
  names the S3 protocol for compatibility only.

## Data and API references

CSPortal ships no third-party data. At run time it reads the operator's own StorageGRID
system through the publicly documented Grid Management API and Tenant Management API
(see [docs/STORAGEGRID_INTEGRATION.md](docs/STORAGEGRID_INTEGRATION.md)). Each source's own
terms of use apply to that use.
