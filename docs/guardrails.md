# Guardrails: from YAML to production

Py2FW runs every policy change through eight stages. A change reaches a
device only if it passes all of them, and each stage is a command you can run
on its own in CI.

```text
YAML policy
  1. Parsing                 check / compile / plan          exit 2
  2. Schema validation       check / validate                exit 1-2
  3. Semantic security       check / analyze                 findings
  4. Policy-as-Code          check --baseline --env          exit 1 / 4
  5. Generate config         compile -t <target>             exit 3 (lossy)
  6. Validate & test config  verify / test / compile         exit 5
  7. Review & approval       plan  ->  approve               exit 1 / 6
  8. Controlled deployment   deploy  ->  audit verify        exit 6
```

## 1. YAML parsing

The parser uses PyYAML's safe loader, so tags such as `!!python/object` are
rejected and the YAML can't execute code. It goes one step further than
`yaml.safe_load()` and also rejects **duplicate keys**, reporting both line
numbers. A plain `safe_load` keeps the last duplicate without telling you, so a
reviewer could approve `db: [10.0.0.1]` while a later `db: [0.0.0.0/0]` is what
actually gets compiled. Malformed YAML, or a root that isn't a mapping, is a
`ParseError` (exit 2).

## 2. Schema validation

`parser/schema.py` (pydantic, `extra="forbid"`) and `compiler/validator.py`
enforce the following. Every schema error is reported with its field path and
source line.

- Required fields (`version`, `name`, `action`, a source, a destination and a
  service on every rule) and correct types. Unknown keys are errors, so typos
  are caught.
- Valid CIDR, IP or hostname values. A CIDR with host bits set
  (`10.0.0.5/24`) produces a warning.
- Valid protocols (`tcp`, `udp`, `icmp`, `any`), ports in 1-65535, range
  start ≤ end, and a port present exactly when the protocol needs one.
- Every object, group and service reference resolves. Groups must be
  non-empty and must not reference each other in a cycle.
- Exceptions name an existing rule and give a reason and an expiry date.
  Test endpoints are IPs, object names or `*`.

## 3. Semantic security validation

Analyzers run on the vendor-neutral IR. Groups are resolved and port ranges
are kept as ranges, so a rule is judged by what it actually allows, however
it is written.

| Severity | Finding | Example |
|---|---|---|
| critical | Any to Any | `0.0.0.0/0` -> any destination |
| high | Open SSH / RDP / Telnet / FTP / SMB / VNC / WinRM | `0.0.0.0/0` -> TCP/22, i.e. unrestricted admin access |
| high | Internet to internal database | broad source -> 3306, 5432, 1433, ... |
| high | Broad source to all ports | broad source + `service: [any]` |
| medium | Any destination | internal source -> every destination |
| medium | Allows all services / Wide port range | `any`, or more than 1024 ports |
| medium | Conflicting rules | partial overlap with an earlier rule that has the opposite action |
| medium | Shadowed rule / Duplicate rule | rule can never match / exact repeat |
| low | Redundant rule, unused object/service, cleartext protocol | hygiene |
| low | Missing business justification | rule has no `description` |

## 4. Policy-as-Code enforcement

### Approved security baseline

The security team keeps a baseline file, separate from the policies it
governs. See [examples/baseline.yaml](../examples/baseline.yaml):

```yaml
version: 1
defaults:
  fail_on: high
  forbidden:
    - name: no-admin-from-internet
      source: broad                 # broad | any | [CIDRs]
      ports: [22, 3389, 5985, 5986]
      severity: critical
  tests:                            # mandatory regression tests (stage 6)
    - { name: internet-cannot-ssh, src: 203.0.113.10, dst: "*", port: 22, expect: deny }
environments:
  dev:  { fail_on: critical }
  prod:
    fail_on: medium
    require_fields: [description, owner, ticket]   # business justification
    allow_exceptions: true
    max_exception_days: 30
    required_approvals: 2
    sign_approvals: false
    allowed_targets: [paloalto, aws-sg]
    forbidden:                      # added to the defaults, never replacing them
      - { name: no-cleartext-in-prod, ports: [21, 23, 80], severity: high }
```

Pass it with `--baseline`, or set `PY2FW_BASELINE` once in CI.

### Environment-specific controls

A policy declares `environment: prod`, or you pass `--env prod`. If both are
given and disagree, the check fails, so a prod policy can't be passed through
as dev. An environment can override the default settings. Its `forbidden`
patterns and `tests` are added to the organisation-wide ones, so an
environment can never remove a baseline control. With a baseline in force,
`--fail-on` on the command line can only make the gate stricter.

### Risk severity and exceptions: warning vs. violation

Severity says how risky a finding is. Whether it blocks deployment is decided
by `analyzers/gate.py`:

| Verdict | When | Blocks? |
|---|---|---|
| **violation** | severity ≥ `fail_on` without a usable exception; any `critical` finding; a validation error; a failed regression test | **yes** |
| **waived** | blocking finding covered by an exception the environment accepts | no, but reported |
| **warning** | below `fail_on`, a validation warning, or an exception that no longer matches anything | no |

An exception is usable only if it gives a reason, hasn't expired, the
environment allows exceptions, and it doesn't run past that environment's
`max_exception_days`. `critical` findings can never be waived.

```yaml
exceptions:
  - { rule: ssh_in, finding: Open SSH, reason: Bastion with MFA, ticket: SEC-42, expires: 2026-12-31 }
```

## 5. Generate vendor configuration

`compile -t <target>` runs all the checks above and refuses to write output
when the gate fails (exit 4), when the target isn't in the environment's
`allowed_targets` (exit 4), or when the target can't express the policy
faithfully (exit 3, unless `--allow-lossy` is passed). Targets: Palo Alto,
FortiGate, Check Point, Cisco ASA, iptables, nftables, AWS security groups,
Azure NSG and Kubernetes NetworkPolicy.

## 6. Configuration validation & testing

- **Syntax validation.** Each exporter checks its own output (`check_syntax`):
  JSON/YAML structure and required keys for AWS, Azure, Check Point and
  Kubernetes, and a line grammar plus block balance for the CLI formats. With
  `--native-syntax`, Py2FW also runs the vendor's own validator where one is
  available (`iptables-restore --test`, `nft -c -f -`).
- **Security regression tests.** The policy's `tests:` and the baseline's
  `tests:` are flows whose decision must never change. `src`/`dst` can be an
  IP, an object name (every address in it is probed) or `*` (every address the
  policy defines). A failing test is a critical, unwaivable violation.
  `py2fw test` runs only the tests.
- **Generated config vs. intended policy.** The output is checked against the
  IR it came from. Every address and port each enabled rule needs must appear
  in it, and it must not contain any address the policy doesn't define. This
  catches exporter bugs such as dropped rules, dropped scope or injected
  addresses. (It already found that the Check Point exporter omitted service
  definitions, and that is fixed.) The check compares tokens, not full
  semantics; rule order and allow/deny decisions are covered by the
  regression tests, which run against the same IR.

`py2fw verify <policy> -t <target>` runs the config checks on their own.
`compile`, `plan` and `deploy` always run them and exit 5 on failure.

## 7. Review and approval

```bash
py2fw plan    policy.yaml -t paloalto --author alice -b baseline.yaml -o plan.json
py2fw approve plan.json --by bob   -m "reviewed CHG-1001"
py2fw approve plan.json --by carol
```

`plan` writes a plan file that contains:

- the gate result, including test results and every waived finding;
- the verification results;
- the **semantic policy diff** and a **unified diff of the generated config**,
  both against what was last deployed to that environment and target;
- the policy and baseline hashes;
- the exact config to deploy.

The `plan_id` is the SHA-256 of that content, so editing the plan file
afterwards invalidates it.

`approve` adds an approval. The author can't approve their own plan, each
approver counts once, and a plan that isn't deployable can't be approved. When
`sign_approvals` is on, approvals must carry an HMAC made with
`PY2FW_APPROVAL_KEY`. Give that key only to approvers, or to a protected CI
environment; without it, an approver name is only what the person typed.

## 8. Controlled deployment and audit

```bash
py2fw deploy plan.json --actor ci --to build/prod-paloalto.cfg \
             --run "ansible-playbook push.yml -e config={config}"
py2fw audit show
py2fw audit verify
```

`deploy` trusts nothing recorded at plan time. Before writing anything it:

1. checks the plan file's `plan_id`;
2. checks the policy and baseline files still match the approved hashes;
3. re-runs every stage: gate, tests, target allow-list, syntax, intent and lossiness;
4. regenerates the config and confirms it is byte-for-byte what was approved;
5. counts valid approvals against the environment's `required_approvals`.

Only then does it write the config atomically and, optionally, run the deploy
command with `{config}` replaced by the file's path. The command runs without
a shell. Every plan, approval, refusal, failure and deployment is appended to
`.py2fw/audit.jsonl`. Each entry contains the hash of the one before it, so
`audit verify` detects any edited, reordered or deleted entry. To protect
against the whole file being replaced, ship the log to WORM storage or your
SIEM.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | gate failed / tests failed / plan not deployable / audit log tampered |
| 2 | malformed input: YAML, schema, validation, baseline, environment mismatch, unknown target |
| 3 | target would lose policy semantics (`--allow-lossy` to accept) |
| 4 | blocking violations, or target not allowed in this environment |
| 5 | generated configuration failed verification |
| 6 | approval or deployment refused |

## CI example

```yaml
# .github/workflows/firewall-policy.yml (in your policy repository)
on: [pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    env: { PY2FW_BASELINE: security/baseline.yaml }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install py2fw
      - run: py2fw check policies/*.yaml
      - run: py2fw plan policies/prod.yaml -t paloalto --author "${{ github.actor }}" -o plan.json
      - uses: actions/upload-artifact@v4
        with: { name: plan, path: plan.json }
```

Protect `security/baseline.yaml` with CODEOWNERS so only the security team
can change it. Make the `gate` job a required check, and run `deploy` only
from a protected environment that holds `PY2FW_APPROVAL_KEY` and the
persistent `.py2fw/` state directory.
