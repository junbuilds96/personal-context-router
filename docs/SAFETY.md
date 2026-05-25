# Safety Boundary

Personal Context Router is built around a small rule: raw private context should
not move straight into an agent prompt.

The current MVP is intentionally simple and local-first:

- Input files stay on your machine.
- Redaction runs before extraction.
- Approval is explicit and required before packet generation.
- Packets are scoped to one agent and one task.
- Requests and writebacks record digests so the routing path is auditable.

## What Not To Commit

Do not commit raw private chats, private notes, credentials, access tokens,
customer data, personal contact details, or copied production prompts. Public
fixtures in this repository must be synthetic.

## Current Redaction Scope

The MVP redacts obvious examples of:

- Email addresses
- Phone-ish numbers
- Lines containing token, secret, password, api_key, access_key, or private_key
- Long hexadecimal strings

This is not a complete data loss prevention system. Treat it as a harness for a
reviewable workflow, not as a guarantee that every sensitive value is removed.

## Human Approval Gate

`pcr approve` requires `--approve-all`. Without it, the command exits nonzero.
That friction is deliberate: context should not become agent input just because
it was extractable.

## Public Demo Policy

Use `examples/sample-note.md` or your own synthetic notes for demos, issues, and
tests. If a bug report needs a reproduction, reduce it to synthetic text first.
