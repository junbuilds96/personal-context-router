# CLI Reference

Install locally:

```bash
python -m pip install -e .
```

Both entrypoints are supported:

```bash
pcr --help
python -m personal_context_router --help
```

Run the full synthetic demo:

```bash
PCR_DEMO="$(mktemp -d)"
pcr run-sample --workdir "$PCR_DEMO"
pcr diagnose "$PCR_DEMO/04-packet.md" --out "$PCR_DEMO/04-diagnostics.md" --json-out "$PCR_DEMO/04-diagnostics.json"
```

Run the pipeline manually:

```bash
PCR_DEMO="$(mktemp -d)"

pcr redact examples/sample-note.md --out "$PCR_DEMO/01-redacted.md"
pcr extract "$PCR_DEMO/01-redacted.md" --source synthetic-sample-note --out "$PCR_DEMO/02-signals.md"
pcr approve "$PCR_DEMO/02-signals.md" --approve-all --out "$PCR_DEMO/03-approved.md"
pcr packet "$PCR_DEMO/03-approved.md" --agent docs-agent --task "draft a README quickstart" --out "$PCR_DEMO/04-packet.md" --json-out "$PCR_DEMO/04-packet.json"
pcr diagnose "$PCR_DEMO/04-packet.md" --out "$PCR_DEMO/04-diagnostics.md" --json-out "$PCR_DEMO/04-diagnostics.json"
pcr request "$PCR_DEMO/04-packet.md" --out "$PCR_DEMO/05-request.md"
pcr writeback "$PCR_DEMO/05-request.md" --out "$PCR_DEMO/06-writeback.md" --status sufficient --note "Packet contained enough synthetic context." --decision-out "$PCR_DEMO/07-decision.md"
```

`pcr approve` treats signal bullet lines as 1-based selectable items. Use
`--approve-all` to approve everything, `--select` to include only listed
indexes, or `--reject` to include everything except listed indexes:

```bash
pcr approve "$PCR_DEMO/02-signals.md" --select 1,3 --out "$PCR_DEMO/03-selected.md"
pcr approve "$PCR_DEMO/02-signals.md" --reject 2,4 --out "$PCR_DEMO/03-rejected.md"
```

`pcr approve` intentionally fails without `--approve-all`, `--select`, or
`--reject`.

Use `pcr packet --json-out PATH` to also write a deterministic
machine-readable context packet with schema `pcr.context_packet.v1`. The JSON
includes scope fields, the approved digest, packet digest, source filename, and
the approved context text.

`pcr diagnose` validates a generated context packet and writes a Markdown report
with an overall pass/fail and itemized checks. It exits `0` on pass and `1` on
fail after writing the report.

Use `--json-out PATH` to also write a deterministic machine-readable diagnostics
artifact for CI and agent harnesses. The JSON includes the packet filename,
packet digest, overall result, check counts, and itemized checks without
including the raw packet body.

Current checks cover:

- frontmatter and `type: context_packet`
- scoped `agent` and `task` values
- 16-character approved digest presence
- body digest consistency
- absence of leaked `[REDACTED]` markers
- required `Context Packet`, `Scope`, and `Approved Context` sections
