# Personal Context Router v0.1.0

Personal Context Router is a zero-runtime-dependency CLI for turning synthetic
or locally held notes into auditable, task-scoped context handoff artifacts.

## Value

- Builds a deterministic file-based workflow: redact, extract, approve, packet,
  diagnose, request, and writeback.
- Keeps humans in the loop with an explicit approval gate before packet
  generation.
- Produces Markdown artifacts that can be inspected, diffed, archived, and used
  in local scripts.

## Commands

```sh
pcr run-sample --workdir .pcr-smoke
pcr diagnose .pcr-smoke/04-packet.md --out .pcr-smoke/04-diagnostics.md
```

The primary public diagnostics command is `pcr diagnose`. Legacy aliases are
kept hidden for compatibility.

## Safety Boundary

- Runtime dependencies: none.
- Examples and demos: synthetic only.
- The CLI writes local files and does not send context to external services.
- Redaction is a conservative helper, not a guarantee; review artifacts before
  sharing them.

## Verification

Release preparation was designed to pass:

```sh
python -m py_compile src/personal_context_router/*.py
python -m pytest -q
python -m pip install -e '.[dev]'
pcr --help
pcr diagnose --help
make verify
git diff --check
```
