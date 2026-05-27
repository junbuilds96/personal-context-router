# Example Packet Diagnostics Report

This is a manually curated synthetic report excerpt. It mirrors the shape of
`pcr diagnose` output without depending on a specific run timestamp or local
temporary directory.

```markdown
---
type: packet_diagnostics
packet: 04-packet.md
packet_digest: ea3621b39406efa7
overall: pass
---

# Packet Diagnostics

**Overall:** pass

**Packet:** 04-packet.md
**Packet digest:** `ea3621b39406efa7`
**Checks passed:** 13/13

## Checks

| Check | Result | Detail |
| --- | --- | --- |
| frontmatter present | PASS | frontmatter found |
| artifact type is context_packet | PASS | type=context_packet |
| agent is scoped | PASS | agent is scoped |
| task is scoped | PASS | task is scoped |
| approved_digest is present and formatted | PASS | approved_digest is a 16-character lowercase hex digest |
| body digest matches frontmatter | PASS | body records the approved_digest |
| no redaction marker leaked | PASS | redaction marker not found |
| context packet heading present | PASS | # Context Packet heading found |
| scope section present | PASS | ## Scope heading found |
| scope section has guardrails | PASS | scope section includes approval guardrails |
| approved context section present | PASS | ## Approved Context heading found |
| approved context is not empty | PASS | approved context has content |
| body scope matches frontmatter | PASS | body Agent and Task lines match frontmatter |
```

Use the real command for a fresh report:

```bash
pcr diagnose "$PCR_DEMO/04-packet.md" --out "$PCR_DEMO/04-diagnostics.md"
```
