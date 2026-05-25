# Synthetic Messy Project Note

This fixture is synthetic. It is designed to look like a messy working note
without containing private chat logs, real credentials, or personal data.

Project goal: build a local-first context router for multi-agent workflows.
The demo should show how raw notes become redacted, approved, task-scoped
context packets.

Contact from pretend stakeholder: alex.demo@example.test
Pretend callback number: +1 (555) 010-0199
api_key = demo_key_that_should_not_ship
Temporary token: 0123456789abcdef0123456789abcdef

Safety constraints:
- Redact emails, phone-ish values, secret-looking lines, and long hex strings.
- Approval is required before an agent receives extracted context.
- Packets must stay scoped to one agent and one task.
- Writeback should leave an audit trail saying whether context was sufficient.

Agent needs:
- docs-agent needs a concise README explanation.
- cli-agent needs command examples for redact, extract, approve, packet, request, writeback.
- qa-agent needs tests that prove the approval gate blocks unapproved signals.

Open question: should a future version support structured exports?
