# Data Model

Personal Context Router uses readable Markdown artifacts with simple
YAML-ish frontmatter. There is no runtime YAML dependency.

## Pipeline Artifacts

`redacted_note`

- Created by `pcr redact`
- Contains a scrubbed version of the source note
- May include `[REDACTED]` markers

`context_signals`

- Created by `pcr extract`
- Contains deterministic sections such as goals, constraints, agent needs, and
  open questions
- Should not include raw private data

`approved_signals`

- Created by `pcr approve --approve-all`
- Records the approval gate in frontmatter
- Required input for packet generation

`context_packet`

- Created by `pcr packet`
- Scoped to one `agent` and one `task`
- Includes a digest of the approved input

`context_request`

- Created by `pcr request`
- Records that an agent is asking whether the packet is sufficient
- Includes a digest of the packet

`writeback`

- Created by `pcr writeback`
- Records `sufficient` or `insufficient`
- Includes the reviewer note and request digest

`routing_decision`

- Optional artifact created with `pcr writeback --decision-out`
- Summarizes the next routing step

## Why Markdown

The first version optimizes for inspectability. A developer can open each file,
read what happened, and review the chain without a database or service account.
