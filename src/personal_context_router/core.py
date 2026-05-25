"""Core transformations for Personal Context Router.

The public repo intentionally uses synthetic fixtures. Do not commit raw
private chats, private notes, credentials, or personal data as examples.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
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


class ApprovalRequired(ValueError):
    """Raised when signals are not explicitly approved."""


class InvalidPipelineInput(ValueError):
    """Raised when a command receives the wrong pipeline artifact."""


@dataclass(frozen=True)
class Artifact:
    path: Path
    text: str


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


def approve_signals(signals_input: str | Path, output_path: str | Path, approve_all: bool) -> Artifact:
    if not approve_all:
        raise ApprovalRequired("Refusing to approve signals without --approve-all.")

    signals = read_text(signals_input)
    text = document(
        "approved_signals",
        f"""\
        # Approved Context Signals

        Approval: approve-all

        The following redacted signals are approved for packet generation.

        {strip_frontmatter(signals).rstrip()}
        """,
        source=Path(signals_input).name,
        approval="approve-all",
    )
    return write_text(output_path, text)


def create_packet(
    approved_input: str | Path,
    agent: str,
    task: str,
    output_path: str | Path,
) -> Artifact:
    approved = read_text(approved_input)
    fields = parse_frontmatter(approved)
    if fields.get("type") != "approved_signals" or fields.get("approval") != "approve-all":
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
    return write_text(output_path, text)


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
