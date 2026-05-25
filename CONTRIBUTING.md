# Contributing

Thanks for helping improve Personal Context Router. Keep contributions small,
reviewable, and aligned with the local-first safety model.

## Ground Rules

- Use synthetic fixtures only. Do not commit private notes, chats, credentials,
  customer data, or personal contact details.
- Keep runtime dependencies at zero unless there is a clear maintainer-approved
  reason to change that constraint.
- Prefer readable Markdown artifacts and deterministic behavior over hidden
  state or network calls.
- Include focused tests for behavior changes.

## Local Verification

```bash
python -m pip install -e ".[dev]"
make verify
```

Useful manual smoke test:

```bash
make smoke
```

## Pull Requests

Explain the user-facing change, mention any safety implications, and include
the verification commands you ran. Documentation-only changes can say so.
