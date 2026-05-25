# Personal Context Router

Personal context, routed safely.

Personal Context Router is a local-first CLI for turning messy notes, chats, and
project context into redacted, approved, task-scoped context packets for
multi-agent workflows. The first version is intentionally small: no server, no
database, no runtime dependencies, and no magic memory layer.

## Why This Exists

Agent workflows often need context, but dumping raw notes into every agent is a
bad default. It spreads sensitive details, makes prompts harder to audit, and
encourages broad context when the task only needs a narrow slice.

This project explores a safer loop:

1. Redact obvious sensitive values.
2. Extract task-relevant signals.
3. Require explicit approval.
4. Build a packet for one agent and one task.
5. Record request and writeback artifacts for auditability.

## Quickstart

```bash
git clone https://github.com/junbuilds96/personal-context-router.git
cd personal-context-router
python -m pip install -e .
pcr run-sample --workdir /tmp/pcr-demo
```

Inspect the generated files:

```bash
ls -1 /tmp/pcr-demo
sed -n '1,120p' /tmp/pcr-demo/04-packet.md
sed -n '1,120p' /tmp/pcr-demo/06-writeback.md
```

## Manual Demo Workflow

```bash
pcr redact examples/sample-note.md --out /tmp/pcr-demo/01-redacted.md
pcr extract /tmp/pcr-demo/01-redacted.md --source synthetic-sample-note --out /tmp/pcr-demo/02-signals.md
pcr approve /tmp/pcr-demo/02-signals.md --approve-all --out /tmp/pcr-demo/03-approved.md
pcr packet /tmp/pcr-demo/03-approved.md --agent docs-agent --task "draft a README quickstart" --out /tmp/pcr-demo/04-packet.md
pcr request /tmp/pcr-demo/04-packet.md --out /tmp/pcr-demo/05-request.md
pcr writeback /tmp/pcr-demo/05-request.md --out /tmp/pcr-demo/06-writeback.md --status sufficient --note "Packet contained enough synthetic context." --decision-out /tmp/pcr-demo/07-decision.md
```

The approval gate is deliberate:

```bash
pcr approve /tmp/pcr-demo/02-signals.md --out /tmp/pcr-demo/not-approved.md
```

That command fails because `--approve-all` is required.

## Safety Boundary

This repository uses synthetic examples only. Do not commit raw private chats,
private notes, credentials, customer data, or personal contact details.

The MVP redacts obvious emails, phone-ish numbers, secret-looking lines, and
long hexadecimal strings. It is not a complete DLP system. The goal is to make a
safer, inspectable routing loop easy to run and easy to improve.

See [docs/SAFETY.md](docs/SAFETY.md) for the project safety policy.

## Why Not Just RAG Or Memory?

RAG and agent memory answer a different question: "How can the agent retrieve
more context?"

Personal Context Router starts with: "What context is allowed to move, for this
agent, for this task, with an audit trail?"

That means the MVP prioritizes:

- Redaction before extraction
- Human approval before packet generation
- Narrow packets instead of broad memory
- Writebacks that say whether the packet was sufficient
- Plain files that can be reviewed in a pull request

## Commands

- `pcr redact INPUT --out OUTPUT`
- `pcr extract REDACTED_INPUT --source SOURCE --out SIGNALS_OUTPUT`
- `pcr approve SIGNALS_INPUT --approve-all --out APPROVED_OUTPUT`
- `pcr packet APPROVED_INPUT --agent AGENT --task TASK --out PACKET_OUTPUT`
- `pcr request PACKET_INPUT --out REQUEST_OUTPUT`
- `pcr writeback REQUEST_INPUT --out WRITEBACK_OUTPUT --status sufficient|insufficient --note TEXT [--decision-out PATH]`
- `pcr run-sample --workdir DIR`

More detail: [docs/CLI.md](docs/CLI.md) and [docs/DATA_MODEL.md](docs/DATA_MODEL.md).

## Development

```bash
python -m pip install -e ".[dev]"
python -m py_compile src/personal_context_router/*.py
python -m pytest -q
```

## Roadmap

- Stronger redaction rules with previewable diffs
- Per-signal approval instead of approve-all only
- Machine-readable JSON export alongside Markdown
- Pluggable extractors while keeping local-first defaults
- Richer writeback summaries for iterative context repair

## License

MIT
