# Personal Context Router

[![CI](https://github.com/junbuilds96/personal-context-router/actions/workflows/ci.yml/badge.svg)](https://github.com/junbuilds96/personal-context-router/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Stop dumping private notes into every agent.

Personal Context Router is a local-first CLI that turns messy notes, chats, and
project context into redacted, approved, task-scoped context packets with
diagnostics and auditable writebacks. It is intentionally small: plain files,
zero runtime dependencies, no server, no database, and no hidden memory layer.

```text
messy note
   |
   v
redact -> extract signals -> approve -> packet -> diagnose -> request -> writeback
                                            |
                                            v
                                  one agent, one task
```

## Quickstart

```bash
git clone https://github.com/junbuilds96/personal-context-router.git
cd personal-context-router
python -m pip install -e ".[dev]"

PCR_DEMO="$(mktemp -d)"
pcr run-sample --workdir "$PCR_DEMO"
pcr diagnose "$PCR_DEMO/04-packet.md" --out "$PCR_DEMO/04-diagnostics.md"
```

You get reviewable Markdown artifacts:

```bash
find "$PCR_DEMO" -maxdepth 1 -type f | sort
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

`pcr approve` intentionally fails without `--approve-all`:

```bash
pcr approve "$PCR_DEMO/02-signals.md" --out "$PCR_DEMO/not-approved.md"
```

See the value proof in
[examples/case-study-agent-handoff.md](examples/case-study-agent-handoff.md).

## Safety Boundary

This repository uses synthetic examples only. Do not commit raw private chats,
private notes, credentials, customer data, or personal contact details.

The MVP redacts obvious emails, phone-ish numbers, secret-looking lines, and
long hexadecimal strings. See [docs/SAFETY.md](docs/SAFETY.md) for the project
safety policy.

## Commands

- `pcr redact INPUT --out OUTPUT`
- `pcr extract REDACTED_INPUT --source SOURCE --out SIGNALS_OUTPUT`
- `pcr approve SIGNALS_INPUT --approve-all --out APPROVED_OUTPUT`
- `pcr packet APPROVED_INPUT --agent AGENT --task TASK --out PACKET_OUTPUT`
- `pcr diagnose PACKET_INPUT --out DIAGNOSTICS_OUTPUT`
- `pcr request PACKET_INPUT --out REQUEST_OUTPUT`
- `pcr writeback REQUEST_INPUT --out WRITEBACK_OUTPUT --status sufficient|insufficient --note TEXT [--decision-out PATH]`
- `pcr run-sample --workdir DIR`

Module form also works:

```bash
python -m personal_context_router.cli --help
```

More detail: [docs/CLI.md](docs/CLI.md) and [docs/DATA_MODEL.md](docs/DATA_MODEL.md).

## Development

```bash
python -m pip install -e ".[dev]"
make verify
make smoke
```

## Roadmap

- Stronger redaction rules with previewable diffs.
- Per-signal approval instead of approve-all only.
- Machine-readable JSON export alongside Markdown.
- Pluggable extractors while keeping local-first defaults.
- Richer writeback summaries for iterative context repair.

## License

MIT
