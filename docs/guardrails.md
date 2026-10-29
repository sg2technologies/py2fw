# Guardrails: keeping unsafe policy out of production

Py2FW checks a policy in four layers. Each layer runs before anything is
exported.

```text
YAML -> 1. parse & schema -> 2. semantic validation -> 3. risk analysis -> 4. gate -> compile
         (exit 2)              (exit 1 / 2)               (findings)          (exit 1 / 4)
```

## 1. Validating the YAML

| Check | Where | Result |
|---|---|---|
| Well-formed YAML, root is a mapping | `parser/yaml_parser.py` | `ParseError`, exit 2 |
| **Duplicate keys** (e.g. two `db:` objects) | `_StrictLoader` | `ParseError` with both line numbers |
| Strict schema: unknown fields, bad action/protocol, port/protocol mismatch, `version: 1` | `parser/schema.py` (pydantic, `extra="forbid"`) | `ParseError` with field path **and line** |
| Endpoints are valid IP/CIDR/hostnames; ports 1-65535; ranges ordered | `compiler/validator.py` | error |
| Every object/group/service/rule reference exists; groups non-empty | `compiler/validator.py` | error |
| Circular group references | `compiler/resolver.py` | error |
| Exceptions reference an existing rule and state a reason and expiry | schema + validator | error |
| Duplicate values, duplicate rule names, literal hostnames | `compiler/validator.py` | warning |

The YAML loader must reject duplicate keys. A standard YAML loader keeps the
last value without telling you. That lets a reviewer approve
`db: [10.0.0.1]` while the compiler actually uses a later `db: [0.0.0.0/0]`.

## 2. Identifying risky rules

`analyzers/` runs on the vendor-neutral IR. Group references are resolved and
port ranges kept as ranges, so a rule is flagged the same way however it is
written.

| Severity | Finding | Trigger |
|---|---|---|
| critical | Any to Any | broad source (`any` or a large public prefix) to any destination |
| high | Internet to internal database | broad source can reach a DB port (3306, 5432, 1433, ...) |
| high | Open SSH / Telnet / FTP / SMB / RDP / VNC | broad source can reach an admin port |
| high | Broad source to all ports | broad source with an all-ports service |
| medium | Allows all services | internal rule with an all-ports service |
| medium | Wide port range | one service spans more than 1024 ports |
| medium | Any destination | internal source allowed to every destination |
| medium | Disabled rule | dead config that may be re-enabled by mistake |
| low | Cleartext protocol | FTP, Telnet, TFTP, HTTP or SNMP allowed |
| low / medium | Shadowed or duplicate rules, unused objects/services, missing description | hygiene |

`py2fw simulate` and `py2fw explain` let you confirm a suspected risk against a
concrete flow. `py2fw compliance` maps the same facts to PCI DSS, NIST 800-53
and CIS controls.

## 3. Warning vs. policy violation

Severity describes how risky a finding is. Whether the finding blocks
deployment is a separate decision, made by `analyzers/gate.py`:

| Verdict | Meaning | Blocks? |
|---|---|---|
| **violation** | finding at or above `--fail-on` (default `high`) with no valid exception; any `critical` finding; any finding whose exception has expired; any validation error | **yes** |
| **waived** | violation covered by an unexpired exception that states a reason | no (still reported) |
| **warning** | finding below `--fail-on`, validation warning, or an exception that no longer matches anything | no |

`--fail-on low|medium|high|critical` moves the threshold. Use `medium` or
`low` for a stricter environment.

### Exceptions

A team that deliberately accepts a risk records an exception in the policy
file. Because the exception lives in the same file, it is reviewed in the same
pull request as the rule it covers:

```yaml
exceptions:
  - rule: ssh_in            # must name an existing rule
    finding: Open SSH       # exact finding title
    reason: Bastion host, MFA enforced
    ticket: SEC-42          # optional
    expires: 2026-12-31     # required; once past, the finding blocks again
```

Rules for exceptions:

- An exception must state a reason and an expiry date. Permanent exceptions
  are not possible.
- An exception covers one finding on one rule, so it can't hide new problems
  on the same rule.
- `critical` findings can never be waived.
- An exception that no longer matches any finding is reported as a warning,
  so stale exceptions get removed.

## 4. Preventing unsafe configurations from reaching production

- **`py2fw check <policy>...`** is the deployment gate. It parses, validates,
  analyzes and gates one or more policies. Exit codes: 0 = pass,
  1 = violations, 2 = parse/validation error. Add `--json` for
  machine-readable output (PR comments, dashboards).
- **`py2fw compile` runs the same gate itself.** If there are violations it
  writes nothing and exits **4**. There is no flag to skip the gate; the only
  override is a reviewed, time-boxed exception in the policy file. Lossy
  vendor translations are refused separately (exit 3) unless `--allow-lossy`
  is passed.
- **Run the gate in CI as a required check** on the branch that deploys:

```yaml
# .github/workflows/firewall-policy.yml (in your policy repository)
name: firewall-policy
on: [pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install py2fw
      - run: py2fw check policies/*.yaml
      - run: git show origin/main:policies/prod.yaml > base.yaml
      - run: py2fw diff base.yaml policies/prod.yaml
```

Make that job a required status check under branch protection, require
review via CODEOWNERS on `policies/`, and generate device configs only from
`main` with `py2fw compile`. A policy then reaches production only after it
has passed the gate twice, once in the pull request and once at compile time,
and after a person has approved any exception.
