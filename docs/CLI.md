# CLI Reference

Install locally:

```bash
python -m pip install -e .
```

Run the full synthetic demo:

```bash
pcr run-sample --workdir /tmp/pcr-demo
```

Run the pipeline manually:

```bash
pcr redact examples/sample-note.md --out /tmp/pcr-demo/01-redacted.md
pcr extract /tmp/pcr-demo/01-redacted.md --source synthetic-sample-note --out /tmp/pcr-demo/02-signals.md
pcr approve /tmp/pcr-demo/02-signals.md --approve-all --out /tmp/pcr-demo/03-approved.md
pcr packet /tmp/pcr-demo/03-approved.md --agent docs-agent --task "draft a README quickstart" --out /tmp/pcr-demo/04-packet.md
pcr request /tmp/pcr-demo/04-packet.md --out /tmp/pcr-demo/05-request.md
pcr writeback /tmp/pcr-demo/05-request.md --out /tmp/pcr-demo/06-writeback.md --status sufficient --note "Packet contained enough synthetic context." --decision-out /tmp/pcr-demo/07-decision.md
```

`pcr approve` intentionally fails without `--approve-all`.
