"""Core transformations for Personal Context Router.

The public repo intentionally uses synthetic fixtures. Do not commit raw
private chats, private notes, credentials, or personal data as examples.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from textwrap import dedent


REDACTION_MARKER = "[REDACTED]"

SECRET_LINE_RE = re.compile(
    r"(?im)^.*\b(token|secret|password|api[_-]?key|access[_-]?key|private[_-]?key)\b\s*[:=].*$"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONEISH_RE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)")
LONG_HEX_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")
SHORT_DIGEST_RE = re.compile(r"^[a-f0-9]{16}$")
PLACEHOLDER_SCOPE_VALUES = {
    "*",
    "all",
    "any",
    "everything",
    "n/a",
    "none",
    "tbd",
    "todo",
    "unknown",
    "unknown-agent",
    "unknown-task",
}
BROAD_TASK_RE = re.compile(r"\b(all context|all notes|all tasks|anything|everything|whatever)\b", re.I)


class ApprovalRequired(ValueError):
    """Raised when signals are not explicitly approved."""


class InvalidPipelineInput(ValueError):
    """Raised when a command receives the wrong pipeline artifact."""


@dataclass(frozen=True)
class Artifact:
    path: Path
    text: str


@dataclass(frozen=True)
class DiagnosticCheck:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class DiagnosticResult:
    artifact: Artifact
    passed: bool
    checks: tuple[DiagnosticCheck, ...]
    json_artifact: Artifact | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def write_text(path: str | Path, text: str) -> Artifact:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    return Artifact(output_path, text)


def frontmatter(kind: str, **fields: str) -> str:
    lines = ["---", f"type: {kind}", f"generated_at: {utc_now()}"]
    for key, value in fields.items():
        safe_value = str(value).replace("\n", " ").strip()
        lines.append(f"{key}: {safe_value}")
    lines.append("---")
    return "\n".join(lines)


def document(kind: str, body: str, **fields: str) -> str:
    return f"{frontmatter(kind, **fields)}\n\n{_document_body(body)}\n"


def parse_frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end == -1:
        return {}
    fields: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    return fields


def strip_frontmatter(text: str) -> str:
    if not text.startswith("---\n"):
        return text
    end = text.find("\n---", 4)
    if end == -1:
        return text
    return text[end + 5 :].lstrip()


def redact_content(raw_text: str) -> str:
    """Redact obvious high-risk identifiers and credential-looking lines."""
    redacted = SECRET_LINE_RE.sub(REDACTION_MARKER, raw_text)
    redacted = EMAIL_RE.sub(REDACTION_MARKER, redacted)
    redacted = PHONEISH_RE.sub(REDACTION_MARKER, redacted)
    redacted = LONG_HEX_RE.sub(REDACTION_MARKER, redacted)
    return redacted


def redact_file(input_path: str | Path, output_path: str | Path) -> Artifact:
    raw_text = read_text(input_path)
    body = redact_content(raw_text)
    text = (
        f"{frontmatter('redacted_note', source=Path(input_path).name)}\n\n"
        "# Redacted Source\n\n"
        f"{body.rstrip()}\n"
    )
    return write_text(output_path, text)


def extract_signals(redacted_input: str | Path, source: str, output_path: str | Path) -> Artifact:
    redacted = read_text(redacted_input)
    if REDACTION_MARKER not in redacted:
        safety_note = "No redaction markers found; verify the source was synthetic or already scrubbed."
    else:
        safety_note = "Redaction markers present before extraction."

    source_body = strip_frontmatter(redacted)
    goals = _collect_lines(source_body, ("goal", "ship", "build", "mvp", "demo"))
    constraints_source = _section_text(source_body, ("safety constraints", "constraints"))
    constraints = _collect_lines(
        constraints_source or source_body,
        ("safety", "privacy", "redact", "approval", "audit", "local", "scope"),
    )
    agent_source = _section_text(source_body, ("agent needs", "agent"))
    agent_needs = _collect_lines(
        agent_source or source_body,
        ("agent", "packet", "writeback", "request", "cli", "test", "docs"),
    )
    open_questions = _collect_questions(source_body)

    text = document(
        "context_signals",
        f"""\
        # Context Signals

        ## Safety Gate
        - {safety_note}
        - Raw private data must stay outside the repository and outside packets.

        ## Goals
        {_format_bullets(goals, ['Create a small, auditable context packet for the requested task.'])}

        ## Constraints
        {_format_bullets(constraints, ['Keep output redacted, approved, and task-scoped.'])}

        ## Agent Needs
        {_format_bullets(agent_needs, ['Provide only the context needed for the named agent and task.'])}

        ## Open Questions
        {_format_bullets(open_questions, ['No open questions detected in the redacted source.'])}
        """,
        source=source,
    )
    return write_text(output_path, text)


def approve_signals(
    signals_input: str | Path,
    output_path: str | Path,
    approve_all: bool,
    select: str | None = None,
    reject: str | None = None,
) -> Artifact:
    approval_options = sum(
        1 for option in (approve_all, select is not None, reject is not None) if option
    )
    if approval_options == 0:
        raise ApprovalRequired(
            "Refusing to approve signals without --approve-all, --select, or --reject."
        )
    if approval_options > 1:
        raise ValueError("--approve-all, --select, and --reject are mutually exclusive.")

    signals = read_text(signals_input)
    signal_items = _selectable_signal_items(signals)
    rejected_indexes: tuple[int, ...] = ()

    if approve_all:
        selected_indexes = tuple(range(1, len(signal_items) + 1))
        selected_text = strip_frontmatter(signals).rstrip()
        approval = "approve-all"
        body_details = [
            "Approval mode: approve-all",
            f"Selected indexes: {_format_index_audit(selected_indexes)}",
            "Rejected indexes: none",
            f"Total selectable signals: {len(signal_items)}",
        ]
    elif select is not None:
        selected_indexes = _parse_signal_indexes(
            select, total=len(signal_items), option="--select"
        )
        selected_text = _format_bullets(
            [signal_items[index - 1] for index in selected_indexes], []
        )
        approval = "select"
        body_details = [
            "Approval mode: select",
            f"Selected indexes: {_format_index_audit(selected_indexes)}",
            "Rejected indexes: none",
            f"Total selectable signals: {len(signal_items)}",
        ]
    else:
        rejected_indexes = _parse_signal_indexes(
            reject or "", total=len(signal_items), option="--reject"
        )
        rejected = set(rejected_indexes)
        selected_indexes = tuple(
            index for index in range(1, len(signal_items) + 1) if index not in rejected
        )
        selected_text = _format_bullets(
            [signal_items[index - 1] for index in selected_indexes], []
        )
        approval = "reject"
        body_details = [
            "Approval mode: reject",
            f"Selected indexes: {_format_index_audit(selected_indexes)}",
            f"Rejected indexes: {_format_index_audit(rejected_indexes)}",
            f"Total selectable signals: {len(signal_items)}",
        ]

    approval_audit = "\n".join(body_details)
    text = document(
        "approved_signals",
        f"""\
        # Approved Context Signals

        Approval: {approval}
        {approval_audit}

        The following redacted signals are approved for packet generation.

        {selected_text}
        """,
        source=Path(signals_input).name,
        approval=approval,
        selected_indexes=_format_index_audit(selected_indexes),
        rejected_indexes=_format_index_audit(rejected_indexes),
        total_selectable_signals=str(len(signal_items)),
    )
    return write_text(output_path, text)


def create_packet(
    approved_input: str | Path,
    agent: str,
    task: str,
    output_path: str | Path,
    json_output_path: str | Path | None = None,
) -> Artifact:
    approved = read_text(approved_input)
    fields = parse_frontmatter(approved)
    if fields.get("type") != "approved_signals" or fields.get("approval") not in {
        "approve-all",
        "select",
        "reject",
    }:
        raise InvalidPipelineInput("Packet creation requires an approved signals artifact.")

    digest = sha256(approved.encode("utf-8")).hexdigest()[:16]
    text = document(
        "context_packet",
        f"""\
        # Context Packet

        Agent: {agent}
        Task: {task}
        Approved source digest: {digest}

        ## Scope
        - Use this packet only for the named task.
        - Treat all content as already redacted but still sensitive.
        - Do not expand the scope without another approval step.

        ## Approved Context
        {strip_frontmatter(approved).rstrip()}
        """,
        agent=agent,
        task=task,
        approved_digest=digest,
    )
    artifact = write_text(output_path, text)
    if json_output_path is not None:
        write_text(json_output_path, serialize_context_packet_json(artifact.path))
    return artifact


def serialize_context_packet_json(packet_input: str | Path) -> str:
    packet = read_text(packet_input)
    fields = parse_frontmatter(packet)
    if fields.get("type") != "context_packet":
        raise InvalidPipelineInput("JSON packet export requires a context packet.")

    approved_context = _markdown_section(packet, "Approved Context")
    if approved_context is None:
        raise InvalidPipelineInput(
            "JSON packet export requires an Approved Context section."
        )

    payload = {
        "schema": "pcr.context_packet.v1",
        "type": "context_packet",
        "agent": fields.get("agent", ""),
        "task": fields.get("task", ""),
        "approved_digest": fields.get("approved_digest", ""),
        "packet_digest": sha256(packet.encode("utf-8")).hexdigest()[:16],
        "source_filename": Path(packet_input).name,
        "approved_context": approved_context,
    }
    return json.dumps(payload, indent=2) + "\n"


def diagnose_packet(
    packet_input: str | Path,
    output_path: str | Path,
    json_output_path: str | Path | None = None,
) -> DiagnosticResult:
    packet = read_text(packet_input)
    fields = parse_frontmatter(packet)

    agent = fields.get("agent", "")
    task = fields.get("task", "")
    approved_digest = fields.get("approved_digest", "")
    body = strip_frontmatter(packet)
    scope_section = _markdown_section(packet, "Scope")
    approved_context_section = _markdown_section(packet, "Approved Context")

    checks = tuple(
        [
            DiagnosticCheck(
                "frontmatter present",
                bool(fields),
                "frontmatter found" if fields else "frontmatter missing or malformed",
            ),
            DiagnosticCheck(
                "artifact type is context_packet",
                fields.get("type") == "context_packet",
                _frontmatter_detail(fields, "type", "context_packet"),
            ),
            DiagnosticCheck(
                "agent is scoped",
                _is_scoped_agent(agent),
                _scope_detail("agent", agent, min_length=2, max_length=80),
            ),
            DiagnosticCheck(
                "task is scoped",
                _is_scoped_task(task),
                _task_scope_detail(task),
            ),
            DiagnosticCheck(
                "approved_digest is present and formatted",
                bool(SHORT_DIGEST_RE.fullmatch(approved_digest)),
                _digest_detail(approved_digest),
            ),
            DiagnosticCheck(
                "body digest matches frontmatter",
                bool(approved_digest) and f"Approved source digest: {approved_digest}" in body,
                (
                    "body records the approved_digest"
                    if approved_digest and f"Approved source digest: {approved_digest}" in body
                    else "body is missing the approved source digest line"
                ),
            ),
            DiagnosticCheck(
                f"no {REDACTION_MARKER} marker leaked",
                REDACTION_MARKER not in packet,
                (
                    f"{REDACTION_MARKER} marker not found"
                    if REDACTION_MARKER not in packet
                    else f"{REDACTION_MARKER} marker found"
                ),
            ),
            DiagnosticCheck(
                "context packet heading present",
                _has_markdown_heading(packet, "Context Packet"),
                (
                    "# Context Packet heading found"
                    if _has_markdown_heading(packet, "Context Packet")
                    else "# Context Packet heading missing"
                ),
            ),
            DiagnosticCheck(
                "scope section present",
                scope_section is not None,
                "## Scope heading found" if scope_section is not None else "## Scope heading missing",
            ),
            DiagnosticCheck(
                "scope section has guardrails",
                bool(scope_section and _section_has_bullets(scope_section) and "approval" in scope_section.lower()),
                (
                    "scope section includes approval guardrails"
                    if scope_section and _section_has_bullets(scope_section) and "approval" in scope_section.lower()
                    else "scope section should include bullet guardrails and approval language"
                ),
            ),
            DiagnosticCheck(
                "approved context section present",
                approved_context_section is not None,
                (
                    "## Approved Context heading found"
                    if approved_context_section is not None
                    else "## Approved Context heading missing"
                ),
            ),
            DiagnosticCheck(
                "approved context is not empty",
                bool(approved_context_section and approved_context_section.strip()),
                (
                    "approved context has content"
                    if approved_context_section and approved_context_section.strip()
                    else "approved context section is empty"
                ),
            ),
            DiagnosticCheck(
                "body scope matches frontmatter",
                bool(agent and task and f"Agent: {agent}" in body and f"Task: {task}" in body),
                (
                    "body Agent and Task lines match frontmatter"
                    if agent and task and f"Agent: {agent}" in body and f"Task: {task}" in body
                    else "body Agent and Task lines do not match frontmatter"
                ),
            ),
        ]
    )
    passed = all(check.passed for check in checks)
    packet_digest = sha256(packet.encode("utf-8")).hexdigest()[:16]
    text = _diagnostics_report_text(
        packet_name=Path(packet_input).name,
        packet_digest=packet_digest,
        passed=passed,
        checks=checks,
    )
    artifact = write_text(output_path, text)
    json_artifact = None
    if json_output_path is not None:
        json_artifact = write_text(
            json_output_path,
            _diagnostics_report_json_text(
                packet_name=Path(packet_input).name,
                packet_digest=packet_digest,
                passed=passed,
                checks=checks,
            ),
        )
    return DiagnosticResult(artifact, passed, checks, json_artifact)


def create_request(packet_input: str | Path, output_path: str | Path) -> Artifact:
    packet = read_text(packet_input)
    fields = parse_frontmatter(packet)
    if fields.get("type") != "context_packet":
        raise InvalidPipelineInput("Context request creation requires a context packet.")

    digest = sha256(packet.encode("utf-8")).hexdigest()[:16]
    agent = fields.get("agent", "unknown-agent")
    task = fields.get("task", "unknown-task")
    text = document(
        "context_request",
        f"""\
        # Context Request

        Agent: {agent}
        Task: {task}
        Packet digest: {digest}

        ## Request
        The agent requests confirmation that this packet is sufficient for the task.

        ## Audit Trail
        - Packet received: {Path(packet_input).name}
        - Packet digest recorded: {digest}
        - Awaiting writeback status: sufficient or insufficient
        """,
        packet=Path(packet_input).name,
        packet_digest=digest,
        agent=agent,
        task=task,
    )
    return write_text(output_path, text)


def create_writeback(
    request_input: str | Path,
    output_path: str | Path,
    status: str,
    note: str,
    decision_out: str | Path | None = None,
) -> Artifact:
    if status not in {"sufficient", "insufficient"}:
        raise ValueError("status must be one of: sufficient, insufficient")

    request = read_text(request_input)
    fields = parse_frontmatter(request)
    if fields.get("type") != "context_request":
        raise InvalidPipelineInput("Writeback creation requires a context request.")

    request_digest = sha256(request.encode("utf-8")).hexdigest()[:16]
    text = document(
        "writeback",
        f"""\
        # Writeback

        Status: {status}
        Note: {note}
        Request digest: {request_digest}

        ## Audit Trail
        - Request reviewed: {Path(request_input).name}
        - Request digest recorded: {request_digest}
        - Decision captured without adding raw private context.
        """,
        request=Path(request_input).name,
        request_digest=request_digest,
        status=status,
    )
    artifact = write_text(output_path, text)

    if decision_out is not None:
        decision_text = document(
            "routing_decision",
            f"""\
            # Routing Decision

            Status: {status}
            Note: {note}

            Next step: {"Proceed with the packet." if status == "sufficient" else "Request a narrower approved packet."}
            """,
            request=Path(request_input).name,
            writeback=Path(output_path).name,
            status=status,
        )
        write_text(decision_out, decision_text)

    return artifact


def run_sample(workdir: str | Path, sample_path: str | Path | None = None) -> list[Artifact]:
    root = Path(workdir)
    root.mkdir(parents=True, exist_ok=True)

    if sample_path is None:
        sample_path = Path(__file__).resolve().parents[2] / "examples" / "sample-note.md"
    sample_text = read_text(sample_path)
    copied_sample = write_text(root / "sample-note.md", sample_text)

    artifacts = [copied_sample]
    artifacts.append(redact_file(copied_sample.path, root / "01-redacted.md"))
    artifacts.append(
        extract_signals(
            root / "01-redacted.md",
            source="synthetic-sample-note",
            output_path=root / "02-signals.md",
        )
    )
    artifacts.append(approve_signals(root / "02-signals.md", root / "03-approved.md", approve_all=True))
    artifacts.append(
        create_packet(
            root / "03-approved.md",
            agent="demo-agent",
            task="draft a scoped implementation plan",
            output_path=root / "04-packet.md",
        )
    )
    artifacts.append(create_request(root / "04-packet.md", root / "05-request.md"))
    artifacts.append(
        create_writeback(
            root / "05-request.md",
            root / "06-writeback.md",
            status="sufficient",
            note="Synthetic sample packet is enough for the demo task.",
            decision_out=root / "07-decision.md",
        )
    )
    return artifacts


def _selectable_signal_items(signals: str) -> tuple[str, ...]:
    items: list[str] = []
    for line in strip_frontmatter(signals).splitlines():
        match = re.match(r"^\s*-\s+(.+?)\s*$", line)
        if match is None:
            continue
        item = match.group(1).strip()
        if not item or _is_section_label(item):
            continue
        items.append(item)
    return tuple(items)


def _parse_signal_indexes(value: str, total: int, option: str) -> tuple[int, ...]:
    if total == 0:
        raise ValueError(
            f"{option} cannot be used because no selectable signal bullets were found."
        )
    if not value.strip():
        raise ValueError(f"{option} requires a comma-separated list of signal indexes.")

    indexes: list[int] = []
    seen: set[int] = set()
    for raw_part in value.split(","):
        part = raw_part.strip()
        if not part:
            raise ValueError(f"{option} contains an empty index in {value!r}.")
        try:
            index = int(part)
        except ValueError as exc:
            raise ValueError(f"{option} index {part!r} is not an integer.") from exc
        if index < 1:
            raise ValueError(f"{option} index {index} must be 1 or greater.")
        if index > total:
            raise ValueError(
                f"{option} index {index} is out of range; only {total} selectable signals found."
            )
        if index in seen:
            raise ValueError(f"{option} index {index} is duplicated.")
        seen.add(index)
        indexes.append(index)

    return tuple(indexes)


def _format_index_audit(indexes: tuple[int, ...]) -> str:
    if not indexes:
        return "none"
    return ",".join(str(index) for index in indexes)


def _collect_lines(text: str, keywords: tuple[str, ...]) -> list[str]:
    lines: list[str] = []
    for line in text.splitlines():
        normalized = line.strip(" -\t")
        if not normalized or normalized.startswith("#"):
            continue
        if REDACTION_MARKER in normalized or _is_section_label(normalized):
            continue
        lowered = normalized.lower()
        if any(keyword in lowered for keyword in keywords):
            lines.append(normalized)
    return _dedupe(lines)[:6]


def _collect_questions(text: str) -> list[str]:
    return _dedupe(
        line.strip(" -\t")
        for line in text.splitlines()
        if "?" in line and line.strip() and not line.lstrip().startswith("#")
    )[:6]


def _section_text(text: str, labels: tuple[str, ...]) -> str:
    lines: list[str] = []
    in_section = False
    for line in text.splitlines():
        normalized = line.strip(" -\t")
        if _is_section_label(normalized):
            label = normalized[:-1].strip().lower()
            in_section = any(label_name in label for label_name in labels)
            continue
        if in_section:
            if not normalized:
                in_section = False
                continue
            lines.append(line)
    return "\n".join(lines)


def _dedupe(items) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            output.append(item)
    return output


def _format_bullets(items: list[str], fallback: list[str]) -> str:
    selected = items or fallback
    return "\n".join(f"- {item}" for item in selected)


def _diagnostics_report_text(
    packet_name: str,
    packet_digest: str,
    passed: bool,
    checks: tuple[DiagnosticCheck, ...],
) -> str:
    overall = "pass" if passed else "fail"
    passed_count = sum(1 for check in checks if check.passed)
    rows = "\n".join(
        f"| {_escape_table_cell(check.name)} | {'PASS' if check.passed else 'FAIL'} | {_escape_table_cell(check.detail)} |"
        for check in checks
    )
    return (
        "---\n"
        "type: packet_diagnostics\n"
        f"packet: {packet_name}\n"
        f"packet_digest: {packet_digest}\n"
        f"overall: {overall}\n"
        "---\n\n"
        "# Packet Diagnostics\n\n"
        f"**Overall:** {overall}\n\n"
        f"**Packet:** {packet_name}  \n"
        f"**Packet digest:** `{packet_digest}`  \n"
        f"**Checks passed:** {passed_count}/{len(checks)}\n\n"
        "## Checks\n\n"
        "| Check | Result | Detail |\n"
        "| --- | --- | --- |\n"
        f"{rows}\n"
    )


def _diagnostics_report_json_text(
    packet_name: str,
    packet_digest: str,
    passed: bool,
    checks: tuple[DiagnosticCheck, ...],
) -> str:
    passed_count = sum(1 for check in checks if check.passed)
    payload = {
        "schema": "pcr.diagnostics.v1",
        "type": "packet_diagnostics",
        "packet_filename": packet_name,
        "packet_digest": packet_digest,
        "overall": "pass" if passed else "fail",
        "counts": {
            "total": len(checks),
            "passed": passed_count,
            "failed": len(checks) - passed_count,
        },
        "checks": [
            {
                "name": check.name,
                "result": "pass" if check.passed else "fail",
                "detail": check.detail,
            }
            for check in checks
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def _document_body(body: str) -> str:
    """Remove template indentation without shifting interpolated multiline text."""
    lines = dedent(body).splitlines()

    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()

    first_content = next((line for line in lines if line.strip()), "")
    template_indent = re.match(r"^[ \t]*", first_content).group(0)
    if template_indent:
        lines = [
            line[len(template_indent) :] if line.startswith(template_indent) else line
            for line in lines
        ]

    return "\n".join(lines).strip()


def _is_section_label(line: str) -> bool:
    if not line.endswith(":"):
        return False
    label = line[:-1].strip()
    return bool(label) and len(label.split()) <= 4


def _frontmatter_detail(fields: dict[str, str], key: str, expected: str) -> str:
    observed = fields.get(key)
    if observed == expected:
        return f"{key}={expected}"
    if observed:
        return f"expected {key}={expected}; found {observed}"
    return f"expected {key}={expected}; found missing"


def _has_markdown_heading(text: str, heading: str) -> bool:
    pattern = rf"(?m)^#+\s+{re.escape(heading)}\s*$"
    return bool(re.search(pattern, text))


def _markdown_section(text: str, heading: str) -> str | None:
    pattern = rf"(?ms)^##\s+{re.escape(heading)}\s*$\n?(.*?)(?=^##\s+|\Z)"
    match = re.search(pattern, text)
    if match is None:
        return None
    return match.group(1).strip()


def _section_has_bullets(text: str) -> bool:
    return bool(re.search(r"(?m)^-\s+\S", text))


def _is_scoped_agent(value: str) -> bool:
    normalized = value.strip().lower()
    return 2 <= len(value.strip()) <= 80 and normalized not in PLACEHOLDER_SCOPE_VALUES


def _is_scoped_task(value: str) -> bool:
    normalized = value.strip().lower()
    if not 8 <= len(value.strip()) <= 180:
        return False
    if normalized in PLACEHOLDER_SCOPE_VALUES:
        return False
    if BROAD_TASK_RE.search(value):
        return False
    return bool(re.search(r"[A-Za-z]", value))


def _scope_detail(label: str, value: str, min_length: int, max_length: int) -> str:
    stripped = value.strip()
    if not stripped:
        return f"{label} is missing or empty"
    if stripped.lower() in PLACEHOLDER_SCOPE_VALUES:
        return f"{label} uses placeholder value {stripped}"
    if len(stripped) < min_length:
        return f"{label} is too short"
    if len(stripped) > max_length:
        return f"{label} is too long"
    return f"{label} is scoped"


def _task_scope_detail(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return "task is missing or empty"
    if stripped.lower() in PLACEHOLDER_SCOPE_VALUES:
        return f"task uses placeholder value {stripped}"
    if len(stripped) < 8:
        return "task is too short to be specific"
    if len(stripped) > 180:
        return "task is too long for a narrow packet"
    if BROAD_TASK_RE.search(stripped):
        return "task is too broad for a scoped packet"
    if not re.search(r"[A-Za-z]", stripped):
        return "task must include readable text"
    return "task is scoped"


def _digest_detail(value: str) -> str:
    if not value:
        return "approved_digest is missing or empty"
    if not SHORT_DIGEST_RE.fullmatch(value):
        return "approved_digest must be a 16-character lowercase hex digest"
    return "approved_digest is a 16-character lowercase hex digest"


def _escape_table_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
