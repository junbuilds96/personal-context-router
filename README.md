# Personal Context Router

[![CI](https://github.com/junbuilds96/personal-context-router/actions/workflows/ci.yml/badge.svg)](https://github.com/junbuilds96/personal-context-router/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Stop dumping private notes into every agent.

For developers and agent users working from messy notes, chats, and project
context, Personal Context Router is a local-first CLI that produces redacted,
approved, task-scoped Markdown packets for one agent and one task, with
diagnostics and auditable writebacks, so you can hand agents useful context
without shipping raw private notes. It is intentionally small: plain files, zero
runtime dependencies, no server, no database, and no hidden memory layer.

## Quick Start

```bash
git clone https://github.com/junbuilds96/personal-context-router.git
cd personal-context-router
python -m pip install -e ".[dev]"

PCR_DEMO="$(mktemp -d)"
pcr run-sample --workdir "$PCR_DEMO"
pcr diagnose "$PCR_DEMO/04-packet.md" --out "$PCR_DEMO/04-diagnostics.md" --json-out "$PCR_DEMO/04-diagnostics.json"
```

```text
messy note
   |
   v
redact -> extract signals -> approve -> packet -> diagnose -> request -> writeback
                                            |
                                            v
                                  one agent, one task
```

## What You Get After 2 Minutes

A messy synthetic note starts with useful task context mixed with things an
agent should not receive:

```text
Contact from pretend stakeholder: alex.demo@example.test
api_key = demo_key_that_should_not_ship
docs-agent needs a concise README explanation.
```

After `pcr run-sample` and `pcr diagnose`, the agent gets a scoped packet and
an auditable diagnostics report:

```text
Agent: demo-agent
Task: draft a scoped implementation plan
Approved source digest: <16-char digest>
Diagnostics: pass, 13/13 checks
Writeback: sufficient, without adding raw private context
```

See the full [2-minute demo](docs/DEMO.md), the curated
[diagnostics report](examples/diagnostics-report.md), and the
[agent handoff case study](examples/case-study-agent-handoff.md).

You get reviewable Markdown artifacts:

```bash
find "$PCR_DEMO" -maxdepth 1 -type f -exec basename {} \; | sort
sed -n '1,120p' "$PCR_DEMO/04-packet.md"
sed -n '1,120p' "$PCR_DEMO/04-diagnostics.md"
sed -n '1,120p' "$PCR_DEMO/06-writeback.md"
```

The packet is scoped to one agent and task. The diagnostic report checks packet
frontmatter, required sections, digest presence, leaked redaction markers, and
scope sanity. Failed diagnostics exit nonzero after writing the report.

## What It Is

- A deterministic local CLI for building inspectable context handoff artifacts.
- A safety gate that requires explicit approval before packet generation.
- A lightweight harness for checking packet shape before handing it to an agent.
- A plain-Markdown audit trail for request and writeback review.

## What It Is Not

- Not a complete DLP system or a guarantee that all sensitive data is removed.
- Not a vector database, RAG framework, agent runtime, or memory service.
- Not a replacement for human review before sharing sensitive context.

## Manual Workflow

```bash
PCR_DEMO="$(mktemp -d)"

pcr redact examples/sample-note.md --out "$PCR_DEMO/01-redacted.md"
pcr extract "$PCR_DEMO/01-redacted.md" --source synthetic-sample-note --out "$PCR_DEMO/02-signals.md"
pcr approve "$PCR_DEMO/02-signals.md" --approve-all --out "$PCR_DEMO/03-approved.md"
pcr packet "$PCR_DEMO/03-approved.md" --agent docs-agent --task "draft a README quickstart" --out "$PCR_DEMO/04-packet.md"
pcr diagnose "$PCR_DEMO/04-packet.md" --out "$PCR_DEMO/04-diagnostics.md"
pcr request "$PCR_DEMO/04-packet.md" --out "$PCR_DEMO/05-request.md"
pcr writeback "$PCR_DEMO/05-request.md" --out "$PCR_DEMO/06-writeback.md" --status sufficient --note "Packet contained enough synthetic context." --decision-out "$PCR_DEMO/07-decision.md"
```

To approve only selected signal bullets, use comma-separated 1-based indexes:

```bash
pcr approve "$PCR_DEMO/02-signals.md" --select 1,3 --out "$PCR_DEMO/03-selected.md"
pcr approve "$PCR_DEMO/02-signals.md" --reject 2,4 --out "$PCR_DEMO/03-rejected.md"
```

`pcr approve` intentionally fails without `--approve-all`, `--select`, or
`--reject`:

```bash
pcr approve "$PCR_DEMO/02-signals.md" --out "$PCR_DEMO/not-approved.md"
```

See the value proof in
[docs/DEMO.md](docs/DEMO.md) and the longer
[agent handoff case study](examples/case-study-agent-handoff.md).

## Safety Boundary

This repository uses synthetic examples only. Do not commit raw private chats,
private notes, credentials, customer data, or personal contact details.

The MVP redacts obvious emails, phone-ish numbers, secret-looking lines, and
long hexadecimal strings. See [docs/SAFETY.md](docs/SAFETY.md) for the project
safety policy.

## Commands

- `pcr redact INPUT --out OUTPUT`
- `pcr extract REDACTED_INPUT --source SOURCE --out SIGNALS_OUTPUT`
- `pcr approve SIGNALS_INPUT (--approve-all|--select INDEXES|--reject INDEXES) --out APPROVED_OUTPUT`
- `pcr packet APPROVED_INPUT --agent AGENT --task TASK --out PACKET_OUTPUT`
- `pcr diagnose PACKET_INPUT --out DIAGNOSTICS_OUTPUT [--json-out JSON_OUTPUT]`
- `pcr request PACKET_INPUT --out REQUEST_OUTPUT`
- `pcr writeback REQUEST_INPUT --out WRITEBACK_OUTPUT --status sufficient|insufficient --note TEXT [--decision-out PATH]`
- `pcr run-sample --workdir DIR`

Module form also works:

```bash
python -m personal_context_router.cli --help
```

More detail: [docs/CLI.md](docs/CLI.md) and [docs/DATA_MODEL.md](docs/DATA_MODEL.md).

## Development

CI runs GitHub Actions tests on Python 3.10 through 3.13.

```bash
python -m pip install -e ".[dev]"
make verify
make smoke
```

## Roadmap

- Stronger redaction rules with previewable diffs.
- Machine-readable JSON export alongside Markdown.
- Pluggable extractors while keeping local-first defaults.
- Richer writeback summaries for iterative context repair.

## License

MIT
