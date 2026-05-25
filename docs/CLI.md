# CLI Reference

Install locally:

```bash
python -m pip install -e .
```

Both entrypoints are supported:

```bash
pcr --help
python -m personal_context_router.cli --help
```

Run the full synthetic demo:

```bash
PCR_DEMO="$(mktemp -d)"
pcr run-sample --workdir "$PCR_DEMO"
pcr diagnose "$PCR_DEMO/04-packet.md" --out "$PCR_DEMO/04-diagnostics.md"
```

Run the pipeline manually:

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

`pcr approve` intentionally fails without `--approve-all`.

`pcr diagnose` validates a generated context packet and writes a Markdown report
with an overall pass/fail and itemized checks. It exits `0` on pass and `1` on
fail after writing the report.

Current checks cover:

- frontmatter and `type: context_packet`
- scoped `agent` and `task` values
- 16-character approved digest presence
- body digest consistency
- absence of leaked `[REDACTED]` markers
- required `Context Packet`, `Scope`, and `Approved Context` sections
