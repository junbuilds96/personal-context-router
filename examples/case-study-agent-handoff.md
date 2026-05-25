# Case Study: Agent Handoff Without Oversharing

This example is fully synthetic. It shows the product loop on purposefully messy
project notes, using short excerpts instead of generated walls of text.

## Before: Messy Working Note

```text
Project goal: ship a local-first context router demo.
Pretend stakeholder contact: alex.demo@example.test
api_key = fake_demo_key_do_not_use

Safety constraints:
- Redact contact details and secret-looking lines.
- Approval is required before an agent receives context.
- Packets must stay scoped to one agent and one task.

Agent needs:
- docs-agent needs a concise README explanation.
- qa-agent needs tests that prove the approval gate works.
```

Problem: a docs agent only needs the README goal, safety constraints, and CLI
shape. It does not need the whole note, contact line, or fake key line.

## After: Approved Packet Excerpt

```markdown
---
type: context_packet
agent: docs-agent
task: draft a README quickstart
approved_digest: 25f3c2c8c8b59a01
---

# Context Packet

Agent: docs-agent
Task: draft a README quickstart
Approved source digest: 25f3c2c8c8b59a01

## Scope
- Use this packet only for the named task.
- Treat all content as already redacted but still sensitive.
- Do not expand the scope without another approval step.

## Approved Context
- Project goal: ship a local-first context router demo.
- Approval is required before an agent receives context.
- Packets must stay scoped to one agent and one task.
- docs-agent needs a concise README explanation.
```

Value: the agent gets enough context to act, while the handoff stays narrow and
reviewable.

## Diagnostics Excerpt

```markdown
# Packet Diagnostics

**Overall:** pass
**Checks passed:** 13/13

| Check | Result | Detail |
| --- | --- | --- |
| artifact type is context_packet | PASS | type=context_packet |
| task is scoped | PASS | task is scoped |
| approved_digest is present and formatted | PASS | approved_digest is a 16-character lowercase hex digest |
| no [REDACTED] marker leaked | PASS | [REDACTED] marker not found |
| approved context is not empty | PASS | approved context has content |
```

Value: packet quality is visible in a Markdown report before an agent consumes
it. Failing diagnostics exit nonzero for local scripts and CI-style harnesses.

## Writeback Excerpt

```markdown
# Writeback

Status: sufficient
Note: Packet contained enough synthetic context for the README quickstart.

## Audit Trail
- Request reviewed: 05-request.md
- Request digest recorded: 84d73e6e16e7c6b7
- Decision captured without adding raw private context.
```

Value: the loop records whether the packet was sufficient without copying raw
private notes back into the workflow.
