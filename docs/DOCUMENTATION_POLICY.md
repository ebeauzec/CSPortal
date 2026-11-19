# Documentation policy

The documentation is a deliverable, and it is kept true. It is maintained by the owner and by
whoever works on the code, in the same commit as the change it describes.

## Rules

1. **Same commit.** A change to behaviour, design, security, modules, supported StorageGRID releases
   or dependencies updates the affected pages in the same commit.
2. **Single home.** Each fact lives in one page; other pages link to it.
3. **Index.** [docs/README.md](README.md) lists every page. A new page is added to it.
4. **Status is honest.** A capability is *Planned*, *Built* or *Verified on a real grid*. Nothing
   built only against the simulator is described as verified.
5. **Public sources only.** Statements about StorageGRID cite public documentation. Nothing from
   behind a sign-in, nothing from a customer. See [COMPLIANCE.md](COMPLIANCE.md).
6. **No customer data.** Examples use placeholders (`example-customer`, `grid.example.net`,
   documentation address ranges). Never real names, hosts, keys or addresses.
7. **No tool attribution.** No page names or credits any AI assistant or tool. See ADR-006 in
   [DECISIONS.md](DECISIONS.md).
8. **Plain language.** Simple technical English: short sentences, active voice, one idea per
   sentence, terms defined once and used the same way.
9. **Changelog.** Every release has an entry in [CHANGELOG.md](../CHANGELOG.md): what changed, in
   neutral wording, and what is not verified.

## Page set

| Page | Keeps true |
|---|---|
| [README.md](../README.md) | What CSPortal is, status, how to read the docs |
| [USE_CASES.md](USE_CASES.md) | The journeys offered to customers |
| [TENANT_PARITY.md](TENANT_PARITY.md) | Tenant capabilities, module and release for each |
| [ACCESS_KEYS_GUIDE.md](ACCESS_KEYS_GUIDE.md) | The customer-facing steps for access keys; changes with the `s3-access` pages, whose on-screen text it mirrors |
| [CUSTOMER_CONTROLS.md](CUSTOMER_CONTROLS.md) | What customer users can do, by role, with checks and audit actions; changes with the customer modules |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Principles, components, flows, deployment |
| [MODULES.md](MODULES.md) | Module contract and module list; one `modules/<id>.md` per module |
| [SECURITY.md](SECURITY.md) | Threats, controls, design rules |
| [STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md) | Native API use, supported range, API map |
| [COMPLIANCE.md](COMPLIANCE.md) | Compliance commitments and CSP responsibilities |
| [compliance/CONTROL_MAP.md](compliance/CONTROL_MAP.md) | ISO/IEC 27001 and SOC 2 control map; its rows change in the same commit as the control |
| [ADMIN_CONSOLE.md](ADMIN_CONSOLE.md) | Settings reference, secrets handling, grid connection guide; changes with `settings.py` and the settings pages |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Production install, hardening checklist, backup, upgrade |
| [DEMO.md](DEMO.md) | Demo mode, sample data, demonstration path |
| [docs/README.md](README.md) | Index of every page |
| [runbooks/](runbooks/README.md) | One page per operating task; a change to the commands, settings or screens a runbook uses changes the runbook in the same commit |
| [../deploy/kubernetes/README.md](../deploy/kubernetes/README.md) | Kubernetes manifests; change with the Dockerfile, ports, probes and data layout |
| [OPERATIONS.md](OPERATIONS.md) | Run, recover, diagnose |
| [DECISIONS.md](DECISIONS.md) | Decision log |
| [ROADMAP.md](ROADMAP.md) | Releases and order of work |
| [CHANGELOG.md](../CHANGELOG.md) | Release history |
| [LICENSE](../LICENSE), [LEGAL.md](../LEGAL.md), [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) | Ownership and notices |

## Review before each release

- Every link works; every page is in the index.
- [TENANT_PARITY.md](TENANT_PARITY.md) statuses match the code.
- [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) matches the dependencies.
- The supported StorageGRID range is the same in the README, the integration page and the changelog.
- A scan of the repository finds no real customer data and no tool attribution.
