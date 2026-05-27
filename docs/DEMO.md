# 2-Minute Demo: Packet Without Oversharing

This demo is fully synthetic. It uses the repository sample note, which includes
fake contact details and fake credential-looking lines on purpose.

## Run It

```bash
python -m pip install -e ".[dev]"

PCR_DEMO="$(mktemp -d)"
pcr run-sample --workdir "$PCR_DEMO"
pcr doctor "$PCR_DEMO" --out "$PCR_DEMO/doctor.md"
```

List the generated artifacts:

```bash
find "$PCR_DEMO" -maxdepth 1 -type f -exec basename {} \; | sort
```

Expected artifacts:

```text
01-redacted.md
02-signals.md
03-approved.md
04-packet.md
05-diagnostics.md
06-request.md
07-writeback.md
08-decision.md
doctor.md
sample-note.md
```

Inspect the proof:

```bash
sed -n '1,120p' "$PCR_DEMO/04-packet.md"
sed -n '1,120p' "$PCR_DEMO/05-diagnostics.md"
sed -n '1,80p' "$PCR_DEMO/07-writeback.md"
```

Timestamps and digests will differ on your machine.

## Before: Messy Synthetic Note

The source fixture intentionally contains agent-useful context mixed with unsafe
context:

```text
Project goal: build a local-first context router for multi-agent workflows.
Contact from pretend stakeholder: alex.demo@example.test
Pretend callback number: +1 (555) 010-0199
api_key = demo_key_that_should_not_ship
Temporary token: 0123456789abcdef0123456789abcdef

Agent needs:
- docs-agent needs a concise README explanation.
- qa-agent needs tests that prove the approval gate blocks unapproved signals.
```

## Packet Excerpt: `04-packet.md`

```markdown
---
type: context_packet
generated_at: 2026-05-25T00:00:00+00:00
agent: demo-agent
task: draft a scoped implementation plan
approved_digest: <16-char digest>
---

# Context Packet

Agent: demo-agent
Task: draft a scoped implementation plan
Approved source digest: <16-char digest>

## Scope
- Use this packet only for the named task.
- Treat all content as already redacted but still sensitive.
- Do not expand the scope without another approval step.

## Approved Context
# Approved Context Signals

Approval: approve-all

## Safety Gate
- Redaction markers present before extraction.
- Raw private data must stay outside the repository and outside packets.

## Goals
- Project goal: build a local-first context router for multi-agent workflows.
- The demo should show how raw notes become redacted, approved, task-scoped

## Constraints
- Redact emails, phone-ish values, secret-looking lines, and long hex strings.
- Approval is required before an agent receives extracted context.
- Packets must stay scoped to one agent and one task.
```

## Diagnostics Excerpt: `05-diagnostics.md`

```markdown
# Packet Diagnostics

**Overall:** pass

**Packet:** 04-packet.md
**Packet digest:** `ea3621b39406efa7`
**Checks passed:** 13/13

## Checks

| Check | Result | Detail |
| --- | --- | --- |
| artifact type is context_packet | PASS | type=context_packet |
| agent is scoped | PASS | agent is scoped |
| task is scoped | PASS | task is scoped |
| approved_digest is present and formatted | PASS | approved_digest is a 16-character lowercase hex digest |
| no redaction marker leaked | PASS | redaction marker not found |
| approved context is not empty | PASS | approved context has content |
| body scope matches frontmatter | PASS | body Agent and Task lines match frontmatter |
```

See a compact curated example at
[examples/diagnostics-report.md](../examples/diagnostics-report.md).

## Writeback Excerpt: `07-writeback.md`

```markdown
# Writeback

Status: sufficient
Note: Synthetic sample packet is enough for the demo task.
Request digest: b5804bfcdc6775c0

## Audit Trail
- Request reviewed: 06-request.md
- Request digest recorded: b5804bfcdc6775c0
- Decision captured without adding raw private context.
```

## What Did Not Move Into The Packet

The packet does not include the raw source note. More importantly, these unsafe
synthetic values do not move into `04-packet.md`:

- `alex.demo@example.test`
- `+1 (555) 010-0199`
- `api_key = demo_key_that_should_not_ship`
- `Temporary token: 0123456789abcdef0123456789abcdef`
- The literal `[REDACTED]` markers from the redacted intermediate artifact

That last point matters: the packet is not a pile of redaction scars. It is a
task-scoped, approved Markdown handoff that can be audited before an agent sees
it.
